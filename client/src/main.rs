use anyhow::Result;
use clap::Parser;
use eframe::egui;
use eframe::egui::Color32;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::runtime::{Builder, Runtime};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;

use shared::{
    proto::{
        orchestrator_client::OrchestratorClient, Empty, SessionTasksRequest, TaskRequest,
    },
    LoginRequest, LoginResponse,
};

// ── colour palette ────────────────────────────────────────────────────────────
const BG:         Color32 = Color32::from_rgb(6, 6, 8);
const PANEL:      Color32 = Color32::from_rgb(10, 10, 14);
const CARD:       Color32 = Color32::from_rgb(16, 16, 22);
const BORDER:     Color32 = Color32::from_rgb(28, 28, 40);
const ACCENT:     Color32 = Color32::from_rgb(196, 43, 62);
const ACCENT_DIM: Color32 = Color32::from_rgb(100, 20, 32);
const GREEN:      Color32 = Color32::from_rgb(60, 179, 113);
const AMBER:      Color32 = Color32::from_rgb(210, 165, 50);
const TEXT:       Color32 = Color32::from_rgb(232, 232, 236);
const MUTED:      Color32 = Color32::from_rgb(120, 122, 140);

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Clone)]
struct Args {
    /// gRPC address of the server (for session/task management)
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    grpc: String,
    /// HTTP address of the server (for login)
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,
}

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct UiState {
    auth:        Option<LoginResponse>,
    flash:       Option<String>,
    sessions:    Vec<shared::proto::SessionSnapshot>,
    tasks:       Vec<shared::proto::TaskResult>,
    pending_login: bool,
}

struct App {
    runtime:  Arc<Runtime>,
    args:     Args,
    state:    Arc<RwLock<UiState>>,
    view:     View,
    // login fields
    username: String,
    password: String,
    // session fields
    selected: Option<String>,
    module:   String,
    task_args: String,
    last_refresh: Instant,
}

#[derive(Clone, Copy, PartialEq)]
enum View { Login, Sessions }

// ── App logic ─────────────────────────────────────────────────────────────────

impl App {
    fn new(runtime: Arc<Runtime>, args: Args) -> Self {
        Self {
            runtime,
            args,
            state:        Arc::new(RwLock::new(UiState::default())),
            view:         View::Login,
            username:     String::new(),
            password:     String::new(),
            selected:     None,
            module:       "shell".into(),
            task_args:    String::new(),
            last_refresh: Instant::now() - Duration::from_secs(10),
        }
    }

    fn flash(&self, msg: impl Into<String>) {
        self.state.write().unwrap().flash = Some(msg.into());
    }

    fn token(&self) -> Option<String> {
        self.state.read().unwrap().auth.as_ref().map(|a| a.token.clone())
    }

    fn do_login(&self) {
        let (username, password) = (self.username.clone(), self.password.clone());
        let (server, state) = (self.args.server.clone(), self.state.clone());
        self.state.write().unwrap().pending_login = true;
        self.runtime.spawn(async move {
            match login(&server, &username, &password).await {
                Ok(resp) => {
                    let mut s = state.write().unwrap();
                    s.flash = Some(format!("Logged in as {}", resp.username));
                    s.auth  = Some(resp);
                    s.pending_login = false;
                }
                Err(e) => {
                    let mut s = state.write().unwrap();
                    s.flash = Some(format!("Login failed: {e}"));
                    s.pending_login = false;
                }
            }
        });
    }

    fn do_refresh(&mut self) {
        let Some(token) = self.token() else { return };
        let (grpc, state) = (self.args.grpc.clone(), self.state.clone());
        let selected = self.selected.clone();
        self.runtime.spawn(async move {
            match connect(&grpc).await {
                Ok(mut client) => {
                    if let Ok(resp) = client.list_sessions(auth_req(Empty {}, &token)).await {
                        state.write().unwrap().sessions = resp.into_inner().sessions;
                    }
                    if let Some(sid) = selected {
                        let req = auth_req(SessionTasksRequest { session_id: sid }, &token);
                        if let Ok(resp) = client.list_session_tasks(req).await {
                            state.write().unwrap().tasks = resp.into_inner().tasks;
                        }
                    }
                }
                Err(e) => { state.write().unwrap().flash = Some(format!("Refresh failed: {e}")); }
            }
        });
        self.last_refresh = Instant::now();
    }

    fn do_dispatch(&self) {
        let Some(sid) = self.selected.clone() else { self.flash("No session selected."); return };
        let Some(token) = self.token()         else { self.flash("Not logged in."); return };
        let (grpc, state) = (self.args.grpc.clone(), self.state.clone());
        let args: Vec<String> = self.task_args.split_whitespace().map(str::to_owned).collect();
        let req = TaskRequest { session_id: sid, module: self.module.clone(), args };
        self.runtime.spawn(async move {
            match connect(&grpc).await {
                Ok(mut client) => {
                    match client.task_session(auth_req(req, &token)).await {
                        Ok(r)  => { state.write().unwrap().flash = Some(format!("Queued: {}", r.into_inner().task_id)); }
                        Err(e) => { state.write().unwrap().flash = Some(format!("Dispatch failed: {e}")); }
                    }
                }
                Err(e) => { state.write().unwrap().flash = Some(format!("Connect failed: {e}")); }
            }
        });
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn configure_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.override_text_color             = Some(TEXT);
    v.panel_fill                      = PANEL;
    v.extreme_bg_color                = BG;
    v.faint_bg_color                  = CARD;
    v.window_fill                     = CARD;
    v.widgets.noninteractive.bg_fill  = CARD;
    v.widgets.inactive.bg_fill        = Color32::from_rgb(20, 20, 28);
    v.widgets.hovered.bg_fill         = Color32::from_rgb(30, 14, 20);
    v.widgets.active.bg_fill          = ACCENT_DIM;
    v.selection.bg_fill               = Color32::from_rgba_unmultiplied(196, 43, 62, 60);
    v.window_stroke                   = egui::Stroke::new(1.0, BORDER);
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    ctx.set_visuals(v);

    let mut s = (*ctx.style()).clone();
    s.spacing.item_spacing   = egui::vec2(8.0, 6.0);
    s.spacing.button_padding = egui::vec2(14.0, 8.0);
    ctx.set_style(s);
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        configure_theme(ctx);
        ctx.request_repaint_after(Duration::from_millis(500));

        // Transition Login → Sessions on successful auth
        if self.view == View::Login {
            if self.state.read().unwrap().auth.is_some() {
                self.view = View::Sessions;
                self.do_refresh();
            }
        }

        // Auto-refresh sessions every 5 s
        if self.view == View::Sessions && self.last_refresh.elapsed() > Duration::from_secs(5) {
            self.do_refresh();
        }

        let state = self.state.read().unwrap().clone();

        if self.view == View::Login {
            egui::CentralPanel::default()
                .frame(egui::Frame::default().fill(BG))
                .show(ctx, |ui| render_login(self, ui, &state));
        } else {
            egui::SidePanel::left("nav")
                .exact_width(175.0)
                .resizable(false)
                .frame(egui::Frame::default().fill(PANEL).stroke(egui::Stroke::new(1.0, BORDER)))
                .show(ctx, |ui| render_sidebar(self, ui, &state));
            egui::CentralPanel::default()
                .frame(egui::Frame::default().fill(BG))
                .show(ctx, |ui| render_sessions(self, ui, &state));
        }
    }
}

fn render_login(app: &mut App, ui: &mut egui::Ui, state: &UiState) {
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        ui.add_space(60.0);
        ui.vertical_centered(|ui| {
            ui.set_max_width(420.0);
            ui.label(egui::RichText::new("◈").size(44.0).color(ACCENT));
            ui.add_space(6.0);
            ui.label(egui::RichText::new("W R A I T H").size(32.0).extra_letter_spacing(6.0).strong().color(TEXT));
            ui.label(egui::RichText::new("COMMAND & CONTROL").size(9.0).extra_letter_spacing(3.0).color(MUTED));
            ui.add_space(28.0);

            egui::Frame::new()
                .fill(CARD)
                .stroke(egui::Stroke::new(1.0, Color32::from_rgba_unmultiplied(196, 43, 62, 70)))
                .corner_radius(12.0)
                .inner_margin(egui::Margin::same(24))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    ui.label(egui::RichText::new("Username").size(11.0).color(MUTED));
                    ui.add(egui::TextEdit::singleline(&mut app.username)
                        .hint_text("admin")
                        .desired_width(ui.available_width()));

                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("Password").size(11.0).color(MUTED));
                    let pw = ui.add(egui::TextEdit::singleline(&mut app.password)
                        .password(true)
                        .hint_text("password")
                        .desired_width(ui.available_width()));
                    let enter = pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                    ui.add_space(12.0);
                    let w = ui.available_width();
                    let btn = egui::Button::new(
                        egui::RichText::new(if state.pending_login { "Authenticating…" } else { "Login" }).size(13.0)
                    )
                    .fill(ACCENT_DIM)
                    .stroke(egui::Stroke::new(1.0, ACCENT))
                    .corner_radius(6.0)
                    .min_size(egui::vec2(w, 38.0));

                    if (ui.add_enabled(!state.pending_login, btn).clicked() || enter) && !state.pending_login {
                        app.do_login();
                    }

                    if let Some(msg) = &state.flash {
                        ui.add_space(10.0);
                        egui::Frame::new()
                            .fill(Color32::from_rgba_unmultiplied(196, 43, 62, 30))
                            .corner_radius(6.0)
                            .inner_margin(egui::Margin::same(10))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(msg).size(11.0).color(Color32::from_rgb(220, 140, 150)));
                            });
                    }
                });
        });
    });
}

fn render_sidebar(app: &mut App, ui: &mut egui::Ui, state: &UiState) {
    ui.add_space(20.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new("◈").size(28.0).color(ACCENT));
        ui.label(egui::RichText::new("WRAITH").size(14.0).extra_letter_spacing(3.0).strong().color(TEXT));
        ui.label(egui::RichText::new("C2").size(9.0).extra_letter_spacing(2.0).color(MUTED));
    });
    ui.add_space(16.0);
    ui.separator();
    ui.add_space(10.0);

    nav_item(ui, "◈", "Sessions", true);

    // Bottom: user + lock
    let h = ui.available_height();
    ui.add_space((h - 60.0).max(8.0));
    ui.separator();
    ui.add_space(8.0);
    if let Some(a) = &state.auth {
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new(&a.username).size(11.0).color(TEXT));
            ui.label(egui::RichText::new(&a.role).size(10.0).color(MUTED));
        });
    }
    ui.add_space(6.0);
    ui.vertical_centered(|ui| {
        if ui.add(egui::Button::new(egui::RichText::new("Lock").size(11.0).color(MUTED))
            .fill(Color32::from_rgb(18, 18, 26))
            .stroke(egui::Stroke::new(1.0, BORDER))).clicked()
        {
            let mut s = app.state.write().unwrap();
            s.auth = None;
            s.sessions.clear();
            s.tasks.clear();
            drop(s);
            app.view = View::Login;
        }
    });
}

fn nav_item(ui: &mut egui::Ui, icon: &str, label: &str, active: bool) {
    let fill = if active { Color32::from_rgba_unmultiplied(196, 43, 62, 35) } else { Color32::TRANSPARENT };
    egui::Frame::new().fill(fill).corner_radius(6.0)
        .inner_margin(egui::Margin { left: 14, right: 8, top: 7, bottom: 7 })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(icon).color(if active { ACCENT } else { MUTED }).size(12.0));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(label).color(if active { TEXT } else { MUTED }).size(12.0));
            });
        });
}

fn render_sessions(app: &mut App, ui: &mut egui::Ui, state: &UiState) {
    // Header
    egui::Frame::new().fill(PANEL)
        .inner_margin(egui::Margin { left: 20, right: 20, top: 14, bottom: 14 })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("IMPLANT SESSIONS").size(12.0).extra_letter_spacing(2.0).strong().color(TEXT));
                ui.add_space(10.0);
                let active = state.sessions.iter().filter(|s| s.active).count();
                ui.label(egui::RichText::new(format!("{active} active / {} total", state.sessions.len())).color(MUTED).size(11.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(egui::Button::new(egui::RichText::new("Refresh").size(11.0).color(MUTED))
                        .fill(Color32::from_rgb(18, 18, 26))
                        .stroke(egui::Stroke::new(1.0, BORDER))).clicked()
                    {
                        app.do_refresh();
                    }
                });
            });
        });

    ui.add(egui::Separator::default().horizontal().spacing(0.0));

    let total_h = ui.available_height();
    let console_h = if app.selected.is_some() { 240.0 } else { 0.0 };

    // Session table
    egui::ScrollArea::vertical().id_salt("sess").max_height(total_h - console_h - 2.0)
        .auto_shrink([false, false]).show(ui, |ui| {
        ui.add_space(6.0);
        if state.sessions.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("No active sessions").color(Color32::from_rgb(50, 52, 70)));
                ui.label(egui::RichText::new("Deploy an implant to get started").size(11.0).color(Color32::from_rgb(35, 37, 55)));
            });
            return;
        }

        // Column headers
        egui::Frame::new().fill(Color32::from_rgb(12, 12, 18))
            .inner_margin(egui::Margin { left: 20, right: 20, top: 5, bottom: 5 })
            .show(ui, |ui| {
                egui::Grid::new("hdr").num_columns(6).spacing([16.0, 0.0]).show(ui, |ui| {
                    for h in ["", "HOSTNAME", "USER", "OS / ARCH", "IP", "LAST SEEN"] {
                        ui.label(egui::RichText::new(h).size(9.0).extra_letter_spacing(1.0).color(Color32::from_rgb(70, 72, 90)));
                    }
                    ui.end_row();
                });
            });

        for s in &state.sessions {
            let sel = app.selected.as_deref() == Some(&s.session_id);
            let resp = egui::Frame::new()
                .fill(if sel { Color32::from_rgba_unmultiplied(196, 43, 62, 22) } else { Color32::TRANSPARENT })
                .stroke(if sel { egui::Stroke::new(1.0, Color32::from_rgba_unmultiplied(196, 43, 62, 80)) } else { egui::Stroke::NONE })
                .inner_margin(egui::Margin { left: 20, right: 20, top: 7, bottom: 7 })
                .show(ui, |ui| {
                    egui::Grid::new(format!("r{}", s.session_id)).num_columns(6).spacing([16.0, 0.0]).show(ui, |ui| {
                        let dot = if s.active { GREEN } else { MUTED };
                        ui.colored_label(dot, if s.active { "●" } else { "○" });
                        ui.label(egui::RichText::new(&s.hostname).strong().color(if sel { TEXT } else { Color32::from_rgb(200, 200, 210) }));
                        ui.label(egui::RichText::new(&s.username).color(MUTED).size(12.0));
                        ui.label(egui::RichText::new(format!("{} / {}", s.os, s.arch)).color(MUTED).size(12.0));
                        ui.label(egui::RichText::new(&s.internal_ip).color(MUTED).size(12.0).monospace());
                        ui.label(egui::RichText::new(&s.last_seen).color(Color32::from_rgb(60, 62, 80)).size(10.0));
                        ui.end_row();
                    });
                });

            let id = ui.id().with(format!("r{}", s.session_id));
            if ui.interact(resp.response.rect, id, egui::Sense::click()).clicked() {
                app.selected = Some(s.session_id.clone());
                app.do_refresh();
            }
            ui.add(egui::Separator::default().horizontal().spacing(0.0));
        }
    });

    // Task console
    if app.selected.is_some() {
        ui.add(egui::Separator::default().horizontal().spacing(0.0));
        render_console(app, ui, state);
    }
}

fn render_console(app: &mut App, ui: &mut egui::Ui, state: &UiState) {
    egui::Frame::new().fill(Color32::from_rgb(8, 8, 12))
        .inner_margin(egui::Margin { left: 20, right: 20, top: 10, bottom: 10 })
        .show(ui, |ui| {
            ui.label(egui::RichText::new("TASK CONSOLE").size(9.0).extra_letter_spacing(2.0).color(Color32::from_rgb(70, 72, 90)));
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("module").color(MUTED).size(11.0));
                egui::ComboBox::from_id_salt("mod").width(90.0)
                    .selected_text(egui::RichText::new(&app.module).size(12.0).color(TEXT))
                    .show_ui(ui, |ui| {
                        for m in ["shell","file_get","file_put","proc_list","sysinfo"] {
                            ui.selectable_value(&mut app.module, m.into(), m);
                        }
                    });
                ui.add_space(6.0);
                ui.label(egui::RichText::new("args").color(MUTED).size(11.0));
                ui.add(egui::TextEdit::singleline(&mut app.task_args)
                    .hint_text(match app.module.as_str() { "shell" => "whoami", "file_get" => "/path/to/file", _ => "" })
                    .desired_width(220.0)
                    .font(egui::TextStyle::Monospace));
                ui.add_space(6.0);
                if ui.add(egui::Button::new(egui::RichText::new("Dispatch").size(12.0).color(TEXT))
                    .fill(ACCENT_DIM).stroke(egui::Stroke::new(1.0, ACCENT)).corner_radius(6.0)).clicked()
                {
                    app.do_dispatch();
                }

                // flash inline
                if let Some(msg) = &state.flash {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(msg).size(11.0).color(Color32::from_rgb(180, 140, 150)));
                }
            });

            ui.add_space(6.0);

            egui::ScrollArea::vertical().id_salt("out").max_height(130.0)
                .stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
                    for t in state.tasks.iter().rev().take(30) {
                        let (sym, col) = match t.status.as_str() {
                            "completed" => ("✓", GREEN),
                            "failed"    => ("✗", Color32::from_rgb(210, 70, 70)),
                            "sent"      => ("…", AMBER),
                            _           => ("·", MUTED),
                        };
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(col, sym);
                            ui.label(egui::RichText::new(&t.module).color(ACCENT).size(11.0).monospace());
                            if !t.args.is_empty() {
                                ui.label(egui::RichText::new(t.args.join(" ")).color(MUTED).size(11.0).monospace());
                            }
                        });
                        if !t.output_json.is_empty() {
                            let out = pretty_output(&t.output_json);
                            if !out.is_empty() {
                                egui::Frame::new().fill(Color32::from_rgb(11, 11, 16)).corner_radius(3.0)
                                    .inner_margin(egui::Margin::same(6))
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new(&out).size(11.0).color(Color32::from_rgb(170, 210, 170)).monospace());
                                    });
                            }
                        }
                    }
                    if state.tasks.is_empty() {
                        ui.label(egui::RichText::new("No tasks yet.").size(11.0).color(Color32::from_rgb(45, 47, 65)));
                    }
                });
        });
}

fn pretty_output(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return json.into() };
    if let Some(s) = v.get("stdout").and_then(|x| x.as_str()) { return s.trim().into(); }
    if let Some(s) = v.get("error").and_then(|x| x.as_str())  { return format!("error: {s}"); }
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

// ── Network helpers ───────────────────────────────────────────────────────────

async fn connect(endpoint: &str) -> Result<OrchestratorClient<Channel>> {
    let ch = Channel::from_shared(endpoint.to_owned())?.connect().await?;
    Ok(OrchestratorClient::new(ch))
}

async fn login(server: &str, username: &str, password: &str) -> Result<LoginResponse> {
    let resp = reqwest::Client::new()
        .post(format!("{server}/api/login"))
        .json(&LoginRequest { username: username.into(), password: password.into() })
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("server returned {}", resp.status());
    }
    Ok(resp.json::<LoginResponse>().await?)
}

fn auth_req<T>(body: T, token: &str) -> tonic::Request<T> {
    let mut req = tonic::Request::new(body);
    let v = MetadataValue::try_from(format!("Bearer {token}")).unwrap();
    req.metadata_mut().insert("authorization", v);
    req
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let args = Args::parse();
    let rt   = Arc::new(Builder::new_multi_thread().enable_all().build()?);

    eframe::run_native(
        "Wraith C2",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("Wraith C2")
                .with_maximized(true)
                .with_min_inner_size([800.0, 500.0]),
            ..Default::default()
        },
        Box::new(move |_cc| Ok(Box::new(App::new(rt, args)))),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
