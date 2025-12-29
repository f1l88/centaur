use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct TracingConfig {
    pub level: String,
    pub output: String, // "console", "json", "both"
    pub enable_ansi: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub admin_port: u16,
    pub servers: HashMap<String, ServerConfig>,
    pub upstreams: HashMap<String, UpstreamConfig>,
    pub tracing: Option<TracingConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_addr: Option<String>,
    pub max_body_size: Option<usize>,
    pub addr: String,  // Формат: "IP:port"
    pub upstreams: Vec<String>,  // Список имен upstream
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub addrs: Vec<String>,
    pub use_tls: bool,
    pub sni: String,
    pub waf_rules: String,
}

impl UpstreamConfig {
    // Или если нет поля name, использовать SNI
    pub fn get_identifier(&self) -> &str {
        &self.sni
    }
}

impl Config {
    pub fn load() -> Self {
        let config_path = format!("{}/config.toml", env!("CARGO_MANIFEST_DIR"));
        let config_str = std::fs::read_to_string(&config_path)
            .expect("Failed to read config.toml");
        toml::from_str(&config_str).expect("Failed to parse config.toml")
    }

    pub fn get_admin_port(&self) -> u16 {
        self.admin_port
    }

    // Получить адрес для прослушивания конкретного сервера
    pub fn get_server_listen_addr(&self, server_name: &str) -> Option<String> {
        self.servers
            .get(server_name)
            .and_then(|server| server.listen_addr.clone())
    }

    // Получить максимальный размер тела для конкретного сервера
    pub fn get_server_max_body_size(&self, server_name: &str) -> usize {
        self.servers
            .get(server_name)
            .and_then(|server| server.max_body_size)
            .unwrap_or(10 * 1024 * 1024) // 10MB default
    }

    // Получить все серверы
    pub fn get_servers(&self) -> &HashMap<String, ServerConfig> {
        &self.servers
    }

    // Получить конкретный сервер
    pub fn get_server(&self, name: &str) -> Option<&ServerConfig> {
        self.servers.get(name)
    }
    
    // Получить upstream по имени
    pub fn get_upstream(&self, name: &str) -> Option<&UpstreamConfig> {
        self.upstreams.get(name)
    }

    // Получить все upstream для сервера
    pub fn get_server_upstreams(&self, server_name: &str) -> Vec<&UpstreamConfig> {
        let mut result = Vec::new();
        if let Some(server) = self.servers.get(server_name) {
            for upstream_name in &server.upstreams {
                if let Some(upstream) = self.upstreams.get(upstream_name) {
                    result.push(upstream);
                }
            }
        }
        result
    }
}