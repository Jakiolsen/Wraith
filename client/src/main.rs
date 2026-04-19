use anyhow::{Context, Result};
use clap::Parser;
use eframe::{egui, egui::Color32};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use reqwest::Client as HttpClient;
use shared::proto::orchestrator_client::OrchestratorClient;
use shared::proto::{
    DashboardSnapshot, Empty, JobType, JobUpdate, JobWatchRequest, SubmitJobRequest,
    SubmitJobResponse,
};
use shared::{
    AgentBootstrapTokenResponse, AuditEventRecord, DeviceIdentity, EnrollmentRequest,
    EnrollmentResponse, LoginRequest, LoginResponse, LogoutRequest,
};
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
    #[arg(long, default_value = "certs/client.enrollment.json")]
    pending_enrollment: PathBuf,
}

#[derive(Clone, Default)]
struct UiState {
    dashboard: Option<DashboardSnapshot>,
    active_job: Option<JobUpdate>,
    audit_events: Vec<AuditEventRecord>,
    flash: Option<String>,
    last_enrollment: Option<EnrollmentResponse>,
    auth_session: Option<LoginResponse>,
    enrolled: bool,
    authenticated: bool,
    pending_enrollment: bool,
    pending_login: bool,
    pending_enrollment_request_id: Option<String>,
}

struct ClientApp {
    runtime: Arc<Runtime>,
    args: Args,
    ui_state: Arc<RwLock<UiState>>,
    current_view: AppView,
    selected_agent: usize,
    job_kind: JobSelection,
    log_lines: u32,
    command_args: String,
    selected_command: String,
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PendingEnrollmentState {
    request_id: String,
    private_key_pem: String,
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
    RunCommand,
}

impl JobSelection {
    fn label(self) -> &'static str {
        match self {
            Self::HealthCheck => "Health Check",
            Self::CollectMetrics => "Collect Metrics",
            Self::FetchApplicationLogs => "Fetch App Logs",
            Self::FetchAuditLogs => "Fetch Audit Logs",
            Self::RunCommand => "Run Command",
        }
    }

    fn job_type(self) -> i32 {
        match self {
            Self::HealthCheck => JobType::HealthCheck as i32,
            Self::CollectMetrics => JobType::CollectMetrics as i32,
            Self::FetchApplicationLogs | Self::FetchAuditLogs => JobType::FetchLogs as i32,
            Self::RunCommand => JobType::RunCommand as i32,
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
        let pending = load_pending_enrollment(&args.pending_enrollment).ok().flatten();
        Self {
            runtime,
            args,
            ui_state: Arc::new(RwLock::new(UiState {
                enrolled,
                pending_enrollment_request_id: pending.as_ref().map(|item| item.request_id.clone()),
                flash: Some(if enrolled {
                    "Device certificate found. Complete operator login to continue.".to_owned()
                } else if pending.is_some() {
                    "Enrollment request is pending certificate issuance.".to_owned()
                } else {
                    "No device certificate found. Complete certificate enrollment first.".to_owned()
                }),
                ..Default::default()
            })),
            current_view: AppView::Start,
            selected_agent: 0,
            job_kind: JobSelection::CollectMetrics,
            log_lines: 80,
            command_args: String::new(),
            selected_command: String::new(),
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
        let (token, role) = {
            let state = self.ui_state.read().unwrap();
            if !(state.enrolled && state.authenticated) {
                return;
            }
            (
                state
                    .auth_session
                    .as_ref()
                    .map(|session| session.session_token.clone()),
                state
                    .auth_session
                    .as_ref()
                    .map(|session| session.role.clone())
                    .unwrap_or_default(),
            )
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
            if role == "admin" {
                match fetch_audit(&args, &token).await {
                    Ok(events) => ui_state.write().unwrap().audit_events = events,
                    Err(err) => {
                        ui_state.write().unwrap().flash =
                            Some(format!("Audit refresh failed: {err}"));
                    }
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
        let command_id = if self.job_kind == JobSelection::RunCommand {
            self.selected_command.trim().to_owned()
        } else {
            String::new()
        };
        let command_args = if self.job_kind == JobSelection::RunCommand {
            parse_command_args(&self.command_args)
        } else {
            Vec::new()
        };
        let request = SubmitJobRequest {
            agent_id: agent.id.clone(),
            job_type: self.job_kind.job_type(),
            log_lines: self.log_lines,
            log_source: self.job_kind.log_source().to_owned(),
            command_id,
            command_args,
        };

        self.runtime.spawn(async move {
            match submit_job(&args, &token, request).await {
                Ok(response) => {
                    {
                        let mut state = ui_state.write().unwrap();
                        state.flash =
                            Some(format!("{} [{}]", response.summary, response.status));
                        state.active_job = None;
                    }
                    if let Err(err) = watch_job_stream(&args, &token, &response.job_id, &ui_state).await {
                        ui_state.write().unwrap().flash =
                            Some(format!("Job watch failed: {err}"));
                    }
                }
                Err(err) => {
                    ui_state.write().unwrap().flash =
                        Some(format!("Dispatch failed: {err}"));
                }
            }
        });
    }

    fn issue_bootstrap_token(&self) {
        let token = self
            .ui_state
            .read()
            .unwrap()
            .auth_session
            .as_ref()
            .map(|session| session.session_token.clone());
        let Some(token) = token else {
            self.set_flash("No authenticated session available.");
            return;
        };
        let args = self.args.clone();
        let ui_state = self.ui_state.clone();
        self.runtime.spawn(async move {
            let message = match issue_bootstrap_token(&args, &token).await {
                Ok(response) => format!(
                    "Bootstrap token: {} (expires {})",
                    response.token, response.expires_at
                ),
                Err(err) => format!("Token issuance failed: {err}"),
            };
            ui_state.write().unwrap().flash = Some(message);
        });
    }

    fn disable_selected_agent(&self) {
        let (agent_id, token) = {
            let state = self.ui_state.read().unwrap();
            let agent_id = state
                .dashboard
                .as_ref()
                .and_then(|snapshot| snapshot.agents.get(self.selected_agent))
                .map(|agent| agent.id.clone());
            let token = state
                .auth_session
                .as_ref()
                .map(|session| session.session_token.clone());
            (agent_id, token)
        };
        let (Some(agent_id), Some(token)) = (agent_id, token) else {
            self.set_flash("No agent selected.");
            return;
        };

        let args = self.args.clone();
        let ui_state = self.ui_state.clone();
        self.runtime.spawn(async move {
            let message = match disable_agent(&args, &token, &agent_id).await {
                Ok(()) => format!("Agent {agent_id} disabled"),
                Err(err) => format!("Disable failed: {err}"),
            };
            ui_state.write().unwrap().flash = Some(message);
        });
    }

    fn rotate_selected_agent_token(&self) {
        let (agent_id, token) = {
            let state = self.ui_state.read().unwrap();
            let agent_id = state
                .dashboard
                .as_ref()
                .and_then(|snapshot| snapshot.agents.get(self.selected_agent))
                .map(|agent| agent.id.clone());
            let token = state
                .auth_session
                .as_ref()
                .map(|session| session.session_token.clone());
            (agent_id, token)
        };
        let (Some(agent_id), Some(token)) = (agent_id, token) else {
            self.set_flash("No agent selected.");
            return;
        };

        let args = self.args.clone();
        let ui_state = self.ui_state.clone();
        self.runtime.spawn(async move {
            let message = match rotate_agent_token(&args, &token, &agent_id).await {
                Ok(response) => format!("New inbound token for {agent_id}: {}", response.token),
                Err(err) => format!("Rotate failed: {err}"),
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
                Ok((response, pending)) => {
                    let mut state = ui_state.write().unwrap();
                    state.pending_enrollment = false;
                    state.last_enrollment = Some(response.clone());
                    state.pending_enrollment_request_id =
                        pending.as_ref().map(|item| item.request_id.clone());
                    if response.status == "issued" {
                        state.enrolled = true;
                        state.pending_enrollment_request_id = None;
                        state.flash = Some(format!(
                            "Certificate enrollment complete for {}",
                            response
                                .client_id
                                .clone()
                                .unwrap_or_else(|| "unknown-client".to_owned())
                        ));
                    } else {
                        state.enrolled = false;
                        state.flash = Some(format!(
                            "Enrollment request {} is pending offline CA approval.",
                            response.request_id
                        ));
                    }
                }
                Err(err) => {
                    let mut state = ui_state.write().unwrap();
                    state.pending_enrollment = false;
                    state.flash = Some(format!("Enrollment failed: {err}"));
                }
            }
        });
    }

    fn check_pending_enrollment(&self) {
        let args = self.args.clone();
        let ui_state = self.ui_state.clone();
        {
            let mut state = self.ui_state.write().unwrap();
            state.pending_enrollment = true;
            state.flash = Some("Checking pending enrollment status...".to_owned());
        }
        self.runtime.spawn(async move {
            let request_id = load_pending_enrollment(&args.pending_enrollment)
                .ok()
                .flatten()
                .map(|item| item.request_id);

            let Some(request_id) = request_id else {
                let mut state = ui_state.write().unwrap();
                state.pending_enrollment = false;
                state.pending_enrollment_request_id = None;
                state.flash = Some("No pending enrollment request found.".to_owned());
                return;
            };

            match fetch_enrollment_status(&args, &request_id).await {
                Ok(response) => {
                    let mut state = ui_state.write().unwrap();
                    state.pending_enrollment = false;
                    state.last_enrollment = Some(response.clone());
                    if response.status == "issued" {
                        state.enrolled = true;
                        state.pending_enrollment_request_id = None;
                        state.flash = Some(format!(
                            "Certificate enrollment complete for {}",
                            response
                                .client_id
                                .clone()
                                .unwrap_or_else(|| "unknown-client".to_owned())
                        ));
                    } else {
                        state.pending_enrollment_request_id = Some(response.request_id.clone());
                        state.flash = Some(format!(
                            "Enrollment request {} is still pending.",
                            response.request_id
                        ));
                    }
                }
                Err(err) => {
                    let mut state = ui_state.write().unwrap();
                    state.pending_enrollment = false;
                    state.flash = Some(format!("Enrollment status check failed: {err}"));
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
        let token = self
            .ui_state
            .read()
            .unwrap()
            .auth_session
            .as_ref()
            .map(|session| session.session_token.clone());
        if let Some(token) = token {
            let args = self.args.clone();
            self.runtime.spawn(async move {
                let _ = logout_remote(&args, &token).await;
            });
        }
        let mut state = self.ui_state.write().unwrap();
        state.authenticated = false;
        state.auth_session = None;
        state.dashboard = None;
        state.active_job = None;
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
                            if ui
                                .add_enabled(
                                    state.pending_enrollment_request_id.is_some()
                                        && !state.pending_enrollment,
                                    egui::Button::new("Check Pending Enrollment"),
                                )
                                .clicked()
                            {
                                self.check_pending_enrollment();
                            }
                            if let Some(enrollment) = &state.last_enrollment {
                                ui.add_space(6.0);
                                ui.small(format!("Request ID: {}", enrollment.request_id));
                                if let Some(client_id) = &enrollment.client_id {
                                    ui.small(format!("Client ID: {}", client_id));
                                }
                                if let Some(expires_at) = &enrollment.expires_at {
                                    ui.small(format!("Expires: {}", expires_at));
                                }
                                ui.small(format!("Status: {}", enrollment.status));
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
        let role = state
            .auth_session
            .as_ref()
            .map(|session| session.role.as_str())
            .unwrap_or("viewer");
        let can_submit = matches!(role, "operator" | "admin");
        let can_admin = role == "admin";
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
                            JobSelection::RunCommand,
                        ] {
                            ui.selectable_value(&mut self.job_kind, job, job.label());
                        }
                    });
                if self.job_kind == JobSelection::RunCommand {
                    let commands = snapshot_commands(state, self.selected_agent);
                    if self.selected_command.is_empty() {
                        if let Some(first) = commands.first() {
                            self.selected_command = first.clone();
                        }
                    }
                    egui::ComboBox::from_label("Command")
                        .selected_text(if self.selected_command.is_empty() {
                            "Select command"
                        } else {
                            &self.selected_command
                        })
                        .show_ui(ui, |ui| {
                            for command in commands {
                                ui.selectable_value(
                                    &mut self.selected_command,
                                    command.clone(),
                                    command,
                                );
                            }
                        });
                    ui.label("Arguments");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.command_args)
                            .hint_text("--verbose /var/log/app.log"),
                    );
                } else {
                    ui.add(egui::Slider::new(&mut self.log_lines, 20..=400).text("Log lines"));
                }
                if ui
                    .add_enabled(can_submit, egui::Button::new("Launch Job"))
                    .clicked()
                {
                    self.dispatch_selected_job();
                }

                ui.separator();
                ui.label(egui::RichText::new("Agent Management").strong());
                if ui
                    .add_enabled(can_admin, egui::Button::new("Issue Bootstrap Token"))
                    .clicked()
                {
                    self.issue_bootstrap_token();
                }
                if ui
                    .add_enabled(can_admin, egui::Button::new("Disable Selected Agent"))
                    .clicked()
                {
                    self.disable_selected_agent();
                }
                if ui
                    .add_enabled(can_admin, egui::Button::new("Rotate Agent Inbound Token"))
                    .clicked()
                {
                    self.rotate_selected_agent_token();
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
                    let detail_preview = summarize_job_details(&job.details_json);
                    if !detail_preview.is_empty() {
                        ui.add_space(4.0);
                        ui.monospace(detail_preview);
                    }
                    ui.add_space(8.0);
                }
            } else {
                ui.label("No dashboard data yet.");
            }
        });

        if let Some(job) = &state.active_job {
            ui.add_space(14.0);
            ui.group(|ui| {
                ui.heading("Live Job");
                ui.separator();
                ui.label(format!("{} [{}]", job.summary, job.status));
                ui.small(format!("Job ID: {}", job.job_id));
                ui.small(format!("Action: {}", job.action));
                let output = job_output_text(&job.details_json);
                if !output.is_empty() {
                    egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                        ui.monospace(output);
                    });
                }
            });
        }

        if can_admin {
            ui.add_space(14.0);
            ui.group(|ui| {
                ui.heading("Audit Trail");
                ui.separator();
                for event in state.audit_events.iter().take(10) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new(&event.action).strong());
                        ui.label(format!("{} {}", event.target_type, event.target_id));
                        ui.small(&event.created_at);
                        if let Some(username) = &event.actor_username {
                            ui.label(format!("by {}", username));
                        }
                    });
                }
            });
        }
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
) -> Result<(EnrollmentResponse, Option<PendingEnrollmentState>)> {
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

    let key_pem = key_pair.serialize_pem();
    if response.status == "issued" {
        finalize_issued_enrollment(args, &response, &key_pem)?;
        Ok((response, None))
    } else {
        let pending = PendingEnrollmentState {
            request_id: response.request_id.clone(),
            private_key_pem: key_pem,
        };
        persist_pending_enrollment(&args.pending_enrollment, &pending)?;
        Ok((response, Some(pending)))
    }
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

async fn logout_remote(args: &Args, session_token: &str) -> Result<()> {
    let ca_pem = fs::read(&args.ca_cert)
        .with_context(|| format!("failed reading {}", args.ca_cert.display()))?;
    let http = HttpClient::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem)?)
        .build()
        .context("failed to construct auth client")?;

    http.post(format!("{}/api/v1/auth/logout", args.enrollment_endpoint))
        .json(&LogoutRequest {
            session_token: session_token.to_owned(),
        })
        .send()
        .await
        .context("failed calling logout endpoint")?
        .error_for_status()
        .context("logout rejected by server")?;

    Ok(())
}

async fn issue_bootstrap_token(
    args: &Args,
    session_token: &str,
) -> Result<AgentBootstrapTokenResponse> {
    let http = build_https_client(args)?;
    let response = http
        .post(format!(
            "{}/api/v1/agents/bootstrap-token",
            args.enrollment_endpoint
        ))
        .bearer_auth(session_token)
        .send()
        .await
        .context("failed calling bootstrap token endpoint")?;
    decode_json_response(response).await
}

async fn disable_agent(args: &Args, session_token: &str, agent_id: &str) -> Result<()> {
    let http = build_https_client(args)?;
    let response = http
        .post(format!(
            "{}/api/v1/agents/{}/disable",
            args.enrollment_endpoint, agent_id
        ))
        .bearer_auth(session_token)
        .send()
        .await
        .context("failed calling disable agent endpoint")?;
    decode_empty_response(response).await
}

async fn rotate_agent_token(
    args: &Args,
    session_token: &str,
    agent_id: &str,
) -> Result<AgentBootstrapTokenResponse> {
    let http = build_https_client(args)?;
    let response = http
        .post(format!(
            "{}/api/v1/agents/{}/rotate-token",
            args.enrollment_endpoint, agent_id
        ))
        .bearer_auth(session_token)
        .send()
        .await
        .context("failed calling rotate agent token endpoint")?;
    decode_json_response(response).await
}

async fn fetch_audit(args: &Args, session_token: &str) -> Result<Vec<AuditEventRecord>> {
    let http = build_https_client(args)?;
    let response = http
        .get(format!("{}/api/v1/audit", args.enrollment_endpoint))
        .bearer_auth(session_token)
        .send()
        .await
        .context("failed calling audit endpoint")?;
    decode_json_response(response).await
}

async fn fetch_enrollment_status(args: &Args, request_id: &str) -> Result<EnrollmentResponse> {
    let http = build_https_client(args)?;

    let response = http
        .get(format!(
            "{}/api/v1/enroll/{}",
            args.enrollment_endpoint, request_id
        ))
        .send()
        .await
        .context("failed calling enrollment status endpoint")?
        .error_for_status()
        .context("enrollment status rejected by server")?
        .json::<EnrollmentResponse>()
        .await
        .context("failed decoding enrollment status")?;

    if response.status == "issued" {
        let pending = load_pending_enrollment(&args.pending_enrollment)?
            .ok_or_else(|| anyhow::anyhow!("missing pending enrollment state"))?;
        finalize_issued_enrollment(args, &response, &pending.private_key_pem)?;
    }

    Ok(response)
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

async fn watch_job_stream(
    args: &Args,
    session_token: &str,
    job_id: &str,
    ui_state: &Arc<RwLock<UiState>>,
) -> Result<()> {
    let mut client = connect(args).await?;
    let mut request = tonic::Request::new(JobWatchRequest {
        job_id: job_id.to_owned(),
    });
    attach_auth(&mut request, session_token)?;
    let mut stream = client
        .watch_job(request)
        .await
        .context("job watch request failed")?
        .into_inner();

    while let Some(update) = stream.message().await.context("job watch stream failed")? {
        let finished = matches!(update.status.as_str(), "completed" | "failed");
        let flash = format!("{} [{}]", update.summary, update.status);
        let mut state = ui_state.write().unwrap();
        state.active_job = Some(update);
        state.flash = Some(flash);
        drop(state);
        if finished {
            break;
        }
    }

    Ok(())
}

fn attach_auth<T>(request: &mut tonic::Request<T>, session_token: &str) -> Result<()> {
    let bearer = format!("Bearer {session_token}");
    let value = MetadataValue::try_from(bearer.as_str())
        .context("failed encoding session token for request metadata")?;
    request.metadata_mut().insert("authorization", value);
    Ok(())
}

fn build_https_client(args: &Args) -> Result<HttpClient> {
    let ca_pem = fs::read(&args.ca_cert)
        .with_context(|| format!("failed reading {}", args.ca_cert.display()))?;
    HttpClient::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem)?)
        .build()
        .context("failed to construct HTTPS client")
}

async fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .json::<ApiError>()
            .await
            .map(|payload| payload.error)
            .unwrap_or_else(|_| format!("request failed with {status}"));
        anyhow::bail!(body);
    }
    response.json::<T>().await.context("failed decoding JSON response")
}

async fn decode_empty_response(response: reqwest::Response) -> Result<()> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .json::<ApiError>()
            .await
            .map(|payload| payload.error)
            .unwrap_or_else(|_| format!("request failed with {status}"));
        anyhow::bail!(body);
    }
    Ok(())
}

fn parse_command_args(input: &str) -> Vec<String> {
    input
        .split_whitespace()
        .map(|item| item.to_owned())
        .collect()
}

fn snapshot_commands(state: &UiState, selected_agent: usize) -> Vec<String> {
    state
        .dashboard
        .as_ref()
        .and_then(|snapshot| snapshot.agents.get(selected_agent))
        .map(|agent| agent.commands.clone())
        .unwrap_or_default()
}

fn summarize_job_details(raw: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return String::new();
    };
    if let Some(stdout) = value.get("stdout").and_then(|value| value.as_str()) {
        return stdout.trim().to_owned();
    }
    if let Some(tail) = value.get("tail").and_then(|value| value.as_str()) {
        return tail.trim().to_owned();
    }
    if let Some(error) = value.get("error").and_then(|value| value.as_str()) {
        return error.to_owned();
    }
    if let Some(path) = value.get("path").and_then(|value| value.as_str()) {
        let size = value
            .get("size_bytes")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        return format!("Collected file: {path} ({size} bytes)");
    }
    String::new()
}

fn job_output_text(raw: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return raw.to_owned();
    };

    let mut parts = Vec::new();
    if let Some(stdout) = value.get("stdout").and_then(|value| value.as_str()) {
        if !stdout.trim().is_empty() {
            parts.push(stdout.trim().to_owned());
        }
    }
    if let Some(stderr) = value.get("stderr").and_then(|value| value.as_str()) {
        if !stderr.trim().is_empty() {
            parts.push(stderr.trim().to_owned());
        }
    }

    if parts.is_empty() {
        summarize_job_details(raw)
    } else {
        parts.join("\n\n")
    }
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

fn finalize_issued_enrollment(args: &Args, response: &EnrollmentResponse, private_key_pem: &str) -> Result<()> {
    let cert_pem = response
        .client_certificate_pem
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("issued enrollment missing certificate"))?;
    persist_secure_file(&args.client_key, private_key_pem.as_bytes())?;
    persist_secure_file(&args.client_cert, cert_pem.as_bytes())?;
    if args.pending_enrollment.exists() {
        fs::remove_file(&args.pending_enrollment).ok();
    }
    Ok(())
}

fn load_pending_enrollment(path: &Path) -> Result<Option<PendingEnrollmentState>> {
    if !path.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    serde_json::from_str(&content)
        .map(Some)
        .context("invalid pending enrollment state")
}

fn persist_pending_enrollment(path: &Path, pending: &PendingEnrollmentState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(pending)?)
        .with_context(|| format!("failed writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
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
