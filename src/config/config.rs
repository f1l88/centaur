use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct TracingConfig {
    pub level: String,
    pub output: String, // "console", "json", "both"
    pub enable_ansi: bool,
}

#[derive(Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: Vec<UpstreamConfig>,
    pub tracing: Option<TracingConfig>,
}

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    pub proxy_port: u16,
    pub admin_port: u16,
    pub listen_addr: Option<String>,
    pub max_body_size: Option<usize>,
}

#[derive(Deserialize, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    pub address: String,
    pub use_tls: bool,
    pub sni: String,
    pub waf_rules: String,
}

impl Config {
    pub fn load() -> Self {
        let config_path = format!("{}/config.toml", env!("CARGO_MANIFEST_DIR"));
        let config_str = std::fs::read_to_string(&config_path)
            .expect("Failed to read config.toml");
        toml::from_str(&config_str).expect("Failed to parse config.toml")
    }

    pub fn get_admin_port(&self) -> u16 {
        self.server.admin_port
    }

        pub fn get_listen_addr(&self) -> String {
        self.server.listen_addr
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string())
    }
    
    // pub fn get_max_body_size(&self) -> usize {
    //     self.server.max_body_size.unwrap_or(10 * 1024 * 1024) // 10MB default
    // }
}