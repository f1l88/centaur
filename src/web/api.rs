use std::sync::Arc;
use std::fs;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use tracing::info;

use crate::proxy::manager::ProxyManager;
use crate::web::ui::ui_router;


/// ====== App State ======
#[derive(Clone)]
struct AdminState {
    proxy_manager: Arc<ProxyManager>,
}

/// ====== Handlers ======

async fn health() -> &'static str {
    "WAF proxy is healthy"
}

async fn reload(State(state): State<AdminState>) -> impl IntoResponse {
    match state.proxy_manager.reload_all_rules() {
        Ok(_) => (StatusCode::OK, "All WAF rules reloaded successfully"),
        Err(_e) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to reload WAF rules"),
    }
}

async fn reload_server(State(state): State<AdminState>) -> impl IntoResponse {
    match state.proxy_manager.reload() {
        Ok(_) => (StatusCode::OK, "Server reloaded successfully"),
        Err(_e) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to reload server"),
    }
}

async fn stats(State(state): State<AdminState>) -> impl IntoResponse {
    let info = state.proxy_manager.get_all_rules_info();
    (StatusCode::OK, info)
}

async fn info_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let info = state.proxy_manager.get_server_config_info();
    (StatusCode::OK, info)
}

async fn list_servers(State(state): State<AdminState>) -> impl IntoResponse {
    let servers = state.proxy_manager.get_server_list();
    (StatusCode::OK, servers.join("\n"))
}

async fn server_info(
    Path(server_name): Path<String>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    match state.proxy_manager.get_server_info(&server_name) {
        Some(info) => (StatusCode::OK, info),
        None => (
            StatusCode::NOT_FOUND,
            format!("Server '{}' not found", server_name),
        ),
    }
}

async fn server_config_info(
    Path(server_name): Path<String>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    match state.proxy_manager.get_server_info(&server_name) {
        Some(info) => (StatusCode::OK, info),
        None => (
            StatusCode::NOT_FOUND,
            format!("Server '{}' not found", server_name),
        ),
    }
}

async fn upgrade(State(state): State<AdminState>) -> impl IntoResponse {
    match state.proxy_manager.upgrade_master().await {
        Ok(_) => (StatusCode::ACCEPTED, "Upgrade started"),
        Err(_e) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start upgrade"),
    }
}

async fn logs(State(state): State<AdminState>) -> impl IntoResponse {
        // Путь к файлу логов
    let path = "./logs/attacks.log"; // или укажи свой путь

    // Читаем содержимое файла
    let content = fs::read_to_string(path)
        .unwrap_or_else(|_| "Cannot read log file".to_string());    
    
    (StatusCode::OK, content)
}

/// ====== Server bootstrap ======

pub async fn run_admin_server(port: u16, proxy_manager: Arc<ProxyManager>) {
    let state = AdminState { proxy_manager };

    // ===== API =====
    let api = Router::new()
        .route("/health", get(health))
        .route("/reload", post(reload))
        .route("/reloadserver", post(reload_server))
        .route("/stats", get(stats))
        .route("/info", get(info_handler))
        .route("/server", get(list_servers))
        .route("/server/{name}", get(server_info))
        .route("/upgrade", post(upgrade))
        .route("/logs", get(logs)) 
        .with_state(state.clone());

    // ===== UI =====
    let ui = ui_router(); // <- твой UI

    // ===== APP =====
    let app = Router::new()
        .merge(api)
        .nest("/admin", ui);

    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind admin port");

    info!("Admin API started at http://{addr}");
    info!("Admin UI  started at http://{addr}/admin");

    axum::serve(listener, app)
        .await
        .expect("Admin server failed");
}

