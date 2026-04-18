use anyhow::{Context, Result};
use clap::Parser;
use eframe::{egui, egui::Color32};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use reqwest::Client as HttpClient;
use shared::proto::orchestrator_client::OrchestratorClient;
use shared::proto::{DashboardSnapshot, Empty, JobType, SubmitJobRequest, SubmitJobResponse};
use shared::{DeviceIdentity, EnrollmentRequest, EnrollmentResponse, LoginRequest, LoginResponse};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::runtime::{Builder, Runtime};
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

#[derive(Parser, Debug, Clone)]
struct Args {
    #[arg(long, default_value = "https://127.0.0.1:50051")]
    endpoint: String,
    #[arg(long, default_value = "https://127.0.0.1:5443")]
    enrollment_endpoint: String,
    #[arg(long, default_value = "localhost")]
    domain_name: String,
    #[arg(long, default_value = "certs/ca.crt")]
    ca_cert: PathBuf,
    #[arg(long, default_value = "certs/client.crt")]
    client_cert: PathBuf,
    #[arg(long, default_value = "certs/client.key")]
    client_key: PathBuf,
}

#[derive(Clone, Default)]
struct UiState {
    dashboard: Option<DashboardSnapshot>,
    flash: Option<String>,
    last_enrollment: Option<EnrollmentResponse>,
    auth_session: Option<LoginResponse>,
    enrolled: bool,
    authenticated: bool,
    pending_enrollment: bool,
    pending_login: bool,
}

struct ClientApp {
    runtime: Arc<Runtime>,
    args: Args,
    ui_state: Arc<RwLock<UiState>>,
    current_view: AppView,
    selected_agent: usize,
    job_kind: JobSelection,
    log_lines: u32,
    enrollment_token: String,
    client_name: String,
    validity_days: u32,
    username: String,
    password: String,
    last_refresh: Instant,
    auto_refresh_requested: bool,
}

#[derive(serde::Deserialize)]
struct ApiError {
    error: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppView {
    Start,
    Main,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JobSelection {
    HealthCheck,
    CollectMetrics,
    FetchApplicationLogs,
    FetchAuditLogs,
}

impl JobSelection {
    fn label(self) -> &'static str {
        match self {
            Self::HealthCheck => "Health Check",
            Self::CollectMetrics => "Collect Metrics",
            Self::FetchApplicationLogs => "Fetch App Logs",
            Self::FetchAuditLogs => "Fetch Audit Logs",
        }
    }

    fn job_type(self) -> i32 {
        match self {
            Self::HealthCheck => JobType::HealthCheck as i32,
            Self::CollectMetrics => JobType::CollectMetrics as i32,
            Self::FetchApplicationLogs | Self::FetchAuditLogs => JobType::FetchLogs as i32,
        }
    }

    fn log_source(self) -> &'static str {
        match self {
            Self::FetchAuditLogs => "audit",
            _ => "application",
        }
    }
}

impl ClientApp {
    fn new(runtime: Arc<Runtime>, args: Args) -> Self {
        let enrolled = args.client_cert.exists() && args.client_key.exists();
        Self {
            runtime,
            args,
            ui_state: Arc::new(RwLock::new(UiState {
                enrolled,
                flash: Some(if enrolled {
                    "Device certificate found. Complete operator login to continue.".to_owned()
                } else {
                    "No device certificate found. Complete certificate enrollment first.".to_owned()
                }),
                ..Default::default()
            })),
            current_view: AppView::Start,
            selected_agent: 0,
            job_kind: JobSelection::CollectMetrics,
            log_lines: 80,
            enrollment_token: String::new(),
            client_name: "wraith-operator".to_owned(),
            validity_days: 30,
            username: String::new(),
            password: String::new(),
            last_refresh: Instant::now() - Duration::from_secs(10),
            auto_refresh_requested: false,
        }
    }

    fn configure_theme(ctx: &egui::Context) {
        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(Color32::from_rgb(236, 236, 236));
        visuals.panel_fill = Color32::from_rgb(7, 7, 9);
        visuals.extreme_bg_color = Color32::from_rgb(10, 10, 12);
        visuals.faint_bg_color = Color32::from_rgb(14, 14, 18);
        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(14, 14, 18);
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(18, 18, 22);
        visuals.widgets.active.bg_fill = Color32::from_rgb(150, 20, 32);
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(182, 28, 43);
        visuals.selection.bg_fill = Color32::from_rgb(166, 24, 38);
        visuals.window_fill = Color32::from_rgb(10, 10, 12);
        ctx.set_visuals(visuals);

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(14.0, 10.0);
        style.visuals.window_corner_radius = 18.0.into();
        style.visuals.widgets.noninteractive.corner_radius = 10.0.into();
        style.visuals.widgets.inactive.corner_radius = 10.0.into();
        style.visuals.widgets.active.corner_radius = 10.0.into();
        style.visuals.widgets.hovered.corner_radius = 10.0.into();
        ctx.set_style(style);
    }

    fn set_flash(&self, message: impl Into<String>) {
        self.ui_state.write().unwrap().flash = Some(message.into());
    }

    fn can_enter_main(&self) -> bool {
        let state = self.ui_state.read().unwrap();
        state.enrolled && state.authenticated && state.auth_session.is_some()
    }

    fn sync_view_with_auth(&mut self) {
        if self.can_enter_main() {
            if self.current_view != AppView::Main {
                self.current_view = AppView::Main;
            }
            if !self.auto_refresh_requested {
                self.request_refresh();
                self.auto_refresh_requested = true;
            }
        } else {
            self.current_view = AppView::Start;
            self.auto_refresh_requested = false;
        }
    }

    fn request_refresh(&mut self) {
        let token = {
            let state = self.ui_state.read().unwrap();
            if !(state.enrolled && state.authenticated) {
                return;
            }
            state
                .auth_session
                .as_ref()
                .map(|session| session.session_token.clone())
        };

        let Some(token) = token else {
            self.set_flash("No authenticated session available.");
            return;
        };

        let args = self.args.clone();
        let ui_state = self.ui_state.clone();
        self.runtime.spawn(async move {
            match fetch_dashboard(&args, &token).await {
                Ok(snapshot) => {
                    let mut state = ui_state.write().unwrap();
                    state.dashboard = Some(snapshot);
                    state.flash = Some("Dashboard refreshed over gRPC mTLS.".to_owned());
                }
                Err(err) => {
                    ui_state.write().unwrap().flash = Some(format!("Refresh failed: {err}"));
                }
            }
        });
        self.last_refresh = Instant::now();
    }

    fn dispatch_selected_job(&self) {
        let (dashboard, token) = {
            let state = self.ui_state.read().unwrap();
            (
                state.dashboard.clone(),
                state
                    .auth_session
                    .as_ref()
                    .map(|session| session.session_token.clone()),
            )
        };
        let Some(snapshot) = dashboard else {
            self.set_flash("No dashboard data available yet.");
            return;
        };
        let Some(token) = token else {
            self.set_flash("No authenticated session available.");
            return;
        };
        let Some(agent) = snapshot.agents.get(self.selected_agent) else {
            self.set_flash("No agent selected.");
            return;
        };

        let args = self.args.clone();
        let ui_state = self.ui_state.clone();
        let request = SubmitJobRequest {
            agent_id: agent.id.clone(),
            job_type: self.job_kind.job_type(),
            log_lines: self.log_lines,
            log_source: self.job_kind.log_source().to_owned(),
        };

        self.runtime.spawn(async move {
            let message = match submit_job(&args, &token, request).await {
                Ok(response) => format!("{} [{}]", response.summary, response.status),
                Err(err) => format!("Dispatch failed: {err}"),
            };
            ui_state.write().unwrap().flash = Some(message);
        });
    }

    fn enroll_device(&self) {
        let args = self.args.clone();
        let ui_state = self.ui_state.clone();
        let token = self.enrollment_token.trim().to_owned();
        let client_name = self.client_name.trim().to_owned();
        let validity_days = self.validity_days;

        {
            let mut state = self.ui_state.write().unwrap();
            state.pending_enrollment = true;
            state.flash = Some("Submitting certificate enrollment...".to_owned());
        }
        self.runtime.spawn(async move {
            match enroll(&args, &token, &client_name, validity_days).await {
                Ok(response) => {
                    let mut state = ui_state.write().unwrap();
                    state.pending_enrollment = false;
                    state.enrolled = true;
                    state.last_enrollment = Some(response.clone());
                    state.flash = Some(format!(
                        "Certificate enrollment complete for {}",
                        response.client_id
                    ));
                }
                Err(err) => {
                    let mut state = ui_state.write().unwrap();
                    state.pending_enrollment = false;
                    state.flash = Some(format!("Enrollment failed: {err}"));
                }
            }
        });
    }

    fn login_operator(&self) {
        let username = self.username.trim().to_owned();
        let password = self.password.clone();
        if username.is_empty() || password.is_empty() {
            self.set_flash("Username and password are required.");
            return;
        }

        let args = self.args.clone();
        let ui_state = self.ui_state.clone();
        {
            let mut state = self.ui_state.write().unwrap();
            state.pending_login = true;
            state.flash = Some("Submitting username/password login...".to_owned());
        }
        self.runtime.spawn(async move {
            match login(&args, &username, &password).await {
                Ok(response) => {
                    let mut state = ui_state.write().unwrap();
                    state.pending_login = false;
                    state.authenticated = true;
                    state.auth_session = Some(response.clone());
                    state.flash = Some(format!("Authenticated as {}", response.username));
                }
                Err(err) => {
                    let mut state = ui_state.write().unwrap();
                    state.pending_login = false;
                    state.authenticated = false;
                    state.auth_session = None;
                    state.flash = Some(format!("Login failed: {err}"));
                }
            }
        });
    }

    fn logout(&mut self) {
        let mut state = self.ui_state.write().unwrap();
        state.authenticated = false;
        state.auth_session = None;
        state.dashboard = None;
        state.flash = Some("Operator session cleared.".to_owned());
        drop(state);
        self.password.clear();
        self.current_view = AppView::Start;
        self.auto_refresh_requested = false;
    }

    fn status_pill(ui: &mut egui::Ui, label: &str, active: bool) {
        let fill = if active {
            Color32::from_rgb(110, 18, 29)
        } else {
            Color32::from_rgb(34, 12, 16)
        };
        let text = if active { "Ready" } else { "Pending" };
        egui::Frame::new()
            .fill(fill)
            .corner_radius(999.0)
            .inner_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(label).strong());
                    ui.label("·");
                    ui.label(text);
                });
            });
    }

    fn render_start_view(&mut self, ui: &mut egui::Ui, state: &UiState) {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.set_max_width(520.0);
                    ui.label(
                        egui::RichText::new("WRAITH")
                            .size(15.0)
                            .extra_letter_spacing(6.0)
                            .color(Color32::from_rgb(188, 32, 46)),
                    );
                    ui.add_space(14.0);
                    ui.heading(
                        egui::RichText::new("Operator Login")
                            .size(30.0)
                            .color(Color32::from_rgb(242, 242, 242)),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(
                            "Certificate identity and operator credentials are both required.",
                        )
                        .color(Color32::from_rgb(156, 156, 162)),
                    );
                    ui.add_space(16.0);
                    ui.horizontal_wrapped(|ui| {
                        Self::status_pill(ui, "Device certificate", state.enrolled);
                        Self::status_pill(ui, "Operator login", state.authenticated);
                    });
                    ui.add_space(18.0);

                    egui::Frame::new()
                        .fill(Color32::from_rgba_unmultiplied(12, 12, 15, 245))
                        .stroke(egui::Stroke::new(
                            1.0,
                            Color32::from_rgba_unmultiplied(190, 24, 40, 90),
                        ))
                        .corner_radius(18.0)
                        .inner_margin(egui::Margin::same(20))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());

                            ui.label(
                                egui::RichText::new("Certificate")
                                    .strong()
                                    .color(Color32::from_rgb(192, 36, 51)),
                            );
                            ui.small(if state.enrolled {
                                "A client certificate is already present on this workstation."
                            } else {
                                "Enroll this workstation if no client certificate is present."
                            });
                            ui.add_space(8.0);
                            ui.label("Enrollment token");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.enrollment_token)
                                    .hint_text("wraith-enrollment-dev-2026"),
                            );
                            ui.label("Client name");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.client_name)
                                    .hint_text("wraith-operator"),
                            );
                            ui.add(
                                egui::Slider::new(&mut self.validity_days, 1..=90)
                                    .text("Validity days"),
                            );
                            if ui
                                .add_enabled(
                                    !state.enrolled && !state.pending_enrollment,
                                    egui::Button::new(if state.pending_enrollment {
                                        "Enrolling..."
                                    } else {
                                        "Enroll Device"
                                    }),
                                )
                                .clicked()
                            {
                                self.enroll_device();
                            }
                            if let Some(enrollment) = &state.last_enrollment {
                                ui.add_space(6.0);
                                ui.small(format!("Client ID: {}", enrollment.client_id));
                                ui.small(format!("Expires: {}", enrollment.expires_at));
                            }

                            ui.add_space(18.0);
                            ui.separator();
                            ui.add_space(12.0);

                            ui.label(
                                egui::RichText::new("Credentials")
                                    .strong()
                                    .color(Color32::from_rgb(192, 36, 51)),
                            );
                            ui.small("Authenticate this workstation to an operator account.");
                            ui.add_space(8.0);
                            ui.label("Username");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.username).hint_text("admin"),
                            );
                            ui.label("Password");
                            let password_edit = egui::TextEdit::singleline(&mut self.password)
                                .password(true)
                                .hint_text("Enter operator password");
                            let response = ui.add(password_edit);
                            let submit_with_enter = response.lost_focus()
                                && ui.input(|input| input.key_pressed(egui::Key::Enter));
                            if (ui
                                .add_enabled(
                                    !state.pending_login,
                                    egui::Button::new(if state.pending_login {
                                        "Authenticating..."
                                    } else {
                                        "Authenticate"
                                    }),
                                )
                                .clicked()
                                || submit_with_enter)
                                && !state.pending_login
                            {
                                self.login_operator();
                            }
                            if let Some(session) = &state.auth_session {
                                ui.add_space(6.0);
                                ui.small(format!("Signed in as: {}", session.username));
                                ui.small(format!("Role: {}", session.role));
                                ui.small(format!("Session expires: {}", session.expires_at));
                            }

                            if let Some(message) = &state.flash {
                                ui.add_space(14.0);
                                egui::Frame::new()
                                    .fill(Color32::from_rgba_unmultiplied(120, 16, 29, 44))
                                    .corner_radius(12.0)
                                    .inner_margin(egui::Margin::same(14))
                                    .show(ui, |ui| {
                                        ui.colored_label(Color32::from_rgb(228, 151, 159), message);
                                    });
                            }
                        });
                });
                ui.add_space(20.0);
            });
    }

    fn render_main_view(&mut self, ui: &mut egui::Ui, state: &UiState) {
        ui.horizontal(|ui| {
            ui.label("Main Page");
            if ui.button("Refresh Dashboard").clicked() {
                self.request_refresh();
            }
            if ui.button("Lock").clicked() {
                self.logout();
            }
        });
        ui.add_space(10.0);

        let online = state
            .dashboard
            .as_ref()
            .map(|snapshot| snapshot.agents.iter().filter(|agent| agent.online).count())
            .unwrap_or(0);

        ui.columns(2, |columns| {
            columns[0].group(|ui| {
                ui.heading("Fleet");
                let agent_count = state
                    .dashboard
                    .as_ref()
                    .map(|snapshot| snapshot.agents.len())
                    .unwrap_or(0);
                ui.label(format!("{agent_count} agents visible"));
                ui.label(format!("{online} agents online"));
                ui.separator();

                if let Some(snapshot) = &state.dashboard {
                    for (index, agent) in snapshot.agents.iter().enumerate() {
                        let selected = self.selected_agent == index;
                        let tone = if agent.online {
                            Color32::from_rgb(186, 44, 58)
                        } else {
                            Color32::from_rgb(111, 46, 52)
                        };
                        let card = egui::Frame::new()
                            .fill(if selected {
                                Color32::from_rgb(28, 12, 16)
                            } else {
                                Color32::from_rgb(14, 14, 17)
                            })
                            .stroke(egui::Stroke::new(
                                1.0,
                                if selected {
                                    Color32::from_rgb(150, 20, 32)
                                } else {
                                    Color32::from_rgb(24, 24, 28)
                                },
                            ))
                            .corner_radius(10.0)
                            .inner_margin(egui::Margin::same(12));
                        card.show(ui, |ui| {
                            if ui
                                .selectable_label(
                                    selected,
                                    format!("{} · {}", agent.name, agent.location),
                                )
                                .clicked()
                            {
                                self.selected_agent = index;
                            }
                            ui.colored_label(tone, &agent.status);
                            ui.small(format!("{} · {}", agent.environment, agent.endpoint));
                        });
                        ui.add_space(6.0);
                    }
                } else {
                    ui.label("No dashboard data yet.");
                }
            });

            columns[1].group(|ui| {
                ui.heading("Operations");
                if let Some(snapshot) = &state.dashboard {
                    if let Some(agent) = snapshot.agents.get(self.selected_agent) {
                        ui.label(format!("Target: {}", agent.name));
                    }
                }

                egui::ComboBox::from_label("Job")
                    .selected_text(self.job_kind.label())
                    .show_ui(ui, |ui| {
                        for job in [
                            JobSelection::HealthCheck,
                            JobSelection::CollectMetrics,
                            JobSelection::FetchApplicationLogs,
                            JobSelection::FetchAuditLogs,
                        ] {
                            ui.selectable_value(&mut self.job_kind, job, job.label());
                        }
                    });
                ui.add(egui::Slider::new(&mut self.log_lines, 20..=400).text("Log lines"));
                if ui.button("Launch Job").clicked() {
                    self.dispatch_selected_job();
                }

                if let Some(session) = &state.auth_session {
                    ui.separator();
                    ui.small(format!("Operator: {}", session.username));
                    ui.small(format!("Role: {}", session.role));
                    ui.small(format!("Session expires: {}", session.expires_at));
                }

                if let Some(message) = &state.flash {
                    ui.colored_label(Color32::from_rgb(214, 97, 109), message);
                }
            });
        });

        ui.add_space(14.0);
        ui.group(|ui| {
            ui.heading("Recent Jobs");
            ui.separator();
            if let Some(snapshot) = &state.dashboard {
                for job in snapshot.recent_jobs.iter().take(8) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new(&job.action).strong());
                        ui.label(format!("on {}", job.agent_name));
                        ui.colored_label(
                            match job.status.as_str() {
                                "completed" => Color32::from_rgb(187, 49, 64),
                                "failed" => Color32::from_rgb(127, 69, 73),
                                "running" => Color32::from_rgb(210, 98, 110),
                                _ => Color32::from_rgb(154, 154, 160),
                            },
                            &job.status,
                        );
                        ui.small(&job.submitted_at);
                        ui.label(&job.summary);
                    });
                }
            } else {
                ui.label("No dashboard data yet.");
            }
        });
    }
}

impl eframe::App for ClientApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        Self::configure_theme(ctx);
        ctx.request_repaint_after(Duration::from_millis(250));
        self.sync_view_with_auth();

        if self.current_view == AppView::Main
            && self.last_refresh.elapsed() > Duration::from_secs(5)
        {
            self.request_refresh();
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(Color32::from_rgb(6, 6, 8)))
            .show(ctx, |ui| {
                let rect = ui.max_rect();
                let painter = ui.painter();
                painter.rect_filled(rect, 0.0, Color32::from_rgb(5, 5, 7));
                painter.circle_filled(
                    rect.left_top() + egui::vec2(160.0, 110.0),
                    220.0,
                    Color32::from_rgba_unmultiplied(130, 18, 31, 24),
                );
                painter.circle_filled(
                    rect.right_top() - egui::vec2(130.0, -80.0),
                    260.0,
                    Color32::from_rgba_unmultiplied(70, 10, 20, 36),
                );
                painter.line_segment(
                    [
                        rect.left_top() + egui::vec2(0.0, 92.0),
                        rect.right_top() + egui::vec2(0.0, 92.0),
                    ],
                    egui::Stroke::new(1.0, Color32::from_rgba_unmultiplied(160, 20, 32, 20)),
                );

                let state = self.ui_state.read().unwrap().clone();

                match self.current_view {
                    AppView::Start => self.render_start_view(ui, &state),
                    AppView::Main => self.render_main_view(ui, &state),
                }
            });
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();
    let runtime = Arc::new(
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("wraith-client")
            .build()
            .context("failed to build tokio runtime")?,
    );

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Wraith Operator Console")
            .with_maximized(true),
        ..Default::default()
    };

    let runtime_for_ui = runtime.clone();
    let args_for_ui = args.clone();
    let runner = move |_cc: &eframe::CreationContext<'_>| {
        Ok::<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>>(Box::new(
            ClientApp::new(runtime_for_ui.clone(), args_for_ui.clone()),
        ))
    };

    eframe::run_native("Wraith Operator Console", native_options, Box::new(runner))
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

async fn enroll(
    args: &Args,
    token: &str,
    client_name: &str,
    validity_days: u32,
) -> Result<EnrollmentResponse> {
    let ca_pem = fs::read(&args.ca_cert)
        .with_context(|| format!("failed reading {}", args.ca_cert.display()))?;
    let http = HttpClient::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem)?)
        .build()
        .context("failed to construct enrollment client")?;

    let key_pair = KeyPair::generate().context("failed generating client private key")?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, client_name.to_owned());
    params.distinguished_name = distinguished_name;
    params
        .subject_alt_names
        .push(SanType::DnsName(detect_hostname().try_into()?));
    let csr = params
        .serialize_request(&key_pair)
        .context("failed generating CSR")?;

    let request = EnrollmentRequest {
        enrollment_token: token.to_owned(),
        client_name: client_name.to_owned(),
        csr_pem: csr.pem()?,
        requested_validity_days: validity_days,
        device: DeviceIdentity {
            hostname: detect_hostname(),
            username: detect_username(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            hardware_fingerprint: format!(
                "{}:{}:{}",
                detect_hostname(),
                detect_username(),
                std::env::consts::ARCH
            ),
        },
    };

    let response = http
        .post(format!("{}/api/v1/enroll", args.enrollment_endpoint))
        .json(&request)
        .send()
        .await
        .context("failed calling enrollment endpoint")?
        .error_for_status()
        .context("enrollment rejected by server")?
        .json::<EnrollmentResponse>()
        .await
        .context("failed decoding enrollment response")?;

    persist_secure_file(&args.client_key, key_pair.serialize_pem().as_bytes())?;
    persist_secure_file(
        &args.client_cert,
        response.client_certificate_pem.as_bytes(),
    )?;

    Ok(response)
}

async fn login(args: &Args, username: &str, password: &str) -> Result<LoginResponse> {
    let ca_pem = fs::read(&args.ca_cert)
        .with_context(|| format!("failed reading {}", args.ca_cert.display()))?;
    let http = HttpClient::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem)?)
        .build()
        .context("failed to construct auth client")?;

    let response = http
        .post(format!("{}/api/v1/auth/login", args.enrollment_endpoint))
        .json(&LoginRequest {
            username: username.to_owned(),
            password: password.to_owned(),
        })
        .send()
        .await
        .context("failed calling auth login endpoint")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .json::<ApiError>()
            .await
            .map(|payload| payload.error)
            .unwrap_or_else(|_| format!("server rejected username/password login ({status})"));
        anyhow::bail!(body);
    }

    response
        .json::<LoginResponse>()
        .await
        .context("failed decoding login response")
}

async fn fetch_dashboard(args: &Args, session_token: &str) -> Result<DashboardSnapshot> {
    let mut client = connect(args).await?;
    let mut request = tonic::Request::new(Empty {});
    attach_auth(&mut request, session_token)?;
    client
        .get_dashboard(request)
        .await
        .context("dashboard request failed")
        .map(|response| response.into_inner())
}

async fn submit_job(
    args: &Args,
    session_token: &str,
    request: SubmitJobRequest,
) -> Result<SubmitJobResponse> {
    let mut client = connect(args).await?;
    let mut request = tonic::Request::new(request);
    attach_auth(&mut request, session_token)?;
    client
        .submit_job(request)
        .await
        .context("job submission failed")
        .map(|response| response.into_inner())
}

fn attach_auth<T>(request: &mut tonic::Request<T>, session_token: &str) -> Result<()> {
    let bearer = format!("Bearer {session_token}");
    let value = MetadataValue::try_from(bearer.as_str())
        .context("failed encoding session token for request metadata")?;
    request.metadata_mut().insert("authorization", value);
    Ok(())
}

async fn connect(args: &Args) -> Result<OrchestratorClient<Channel>> {
    let ca = fs::read(&args.ca_cert)
        .with_context(|| format!("failed reading {}", args.ca_cert.display()))?;
    let cert = fs::read(&args.client_cert)
        .with_context(|| format!("failed reading {}", args.client_cert.display()))?;
    let key = fs::read(&args.client_key)
        .with_context(|| format!("failed reading {}", args.client_key.display()))?;

    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key))
        .domain_name(&args.domain_name);

    let channel = Endpoint::from_shared(args.endpoint.clone())?
        .tls_config(tls)?
        .connect()
        .await?;

    Ok(OrchestratorClient::new(channel))
}

fn persist_secure_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.extension().and_then(|ext| ext.to_str()) == Some("key") {
            0o600
        } else {
            0o644
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn detect_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_owned())
}

fn detect_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown-user".to_owned())
}
