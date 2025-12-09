use pingora::server::Server;
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
//use std::collections::HashMap;

use centaur_core::{Engine, SharedWaf};

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Shared map: upstream_name -> SharedWaf
/// RwLock so we can reload engines in-place
type WafMap = Arc<RwLock<HashMap<String, Arc<SharedWaf>>>>;

// struct MyProxy {
//     waf_engines: HashMap<String, Arc<SharedWaf>>, // upstream_name -> WAF
//     config: Config,
// }

#[derive(Deserialize, Clone, Debug)]
struct Config {
    server: ServerConfig,
    upstream: Vec<UpstreamConfig>,
}

#[derive(Debug,Deserialize, Clone)]
struct ServerConfig {
    proxy_port: u16,
    admin_port: u16,
}

#[derive(Deserialize, Clone, Debug)]
struct UpstreamConfig {
    name: String,
    address: String,
    use_tls: bool,
    sni: String,
    waf_rules: String,
}

impl Config {
    pub fn load_from() -> anyhow::Result<Self> {
        let config_path = format!("{}/config.toml", env!("CARGO_MANIFEST_DIR"));
        let config_str = std::fs::read_to_string(&config_path)
            .map_err(|e| anyhow::anyhow!("Failed to read config.toml: {}", e))?;
        let config = toml::from_str(&config_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse config.toml: {}", e))?;
        Ok(config)
    }
}

#[derive(Clone)]
struct AppState {
    config: Config,
    wafs: WafMap,
}

impl AppState {
    async fn load_wafs(config: &Config) -> WafMap {
        let mut map = HashMap::new();
        
        for upstream in &config.upstream {
            let rules_path = format!("{}/rules/{}", env!("CARGO_MANIFEST_DIR"), upstream.waf_rules);
            if !std::path::Path::new(&rules_path).exists() {
                warn!("Reload: rules file does NOT exist: {}", rules_path);
            }
            match Engine::load(&rules_path) {
                Ok(engine) => {
                    map.insert(upstream.name.clone(), Arc::new(SharedWaf::new(engine, rules_path.clone())));
                    info!(upstream = %upstream.name, rules = %upstream.waf_rules, "Loaded WAF rules");
                }
                Err(e) => {
                    warn!(upstream = %upstream.name, err = %e, "Failed to load rules, attempting default");
                    let default_path = format!("{}/rules/default.toml", env!("CARGO_MANIFEST_DIR"));
                    match Engine::load(&default_path) {
                        Ok(engine) => {
                            map.insert(upstream.name.clone(), Arc::new(SharedWaf::new(engine, default_path.clone())));
                            info!(upstream = %upstream.name, "Loaded default rules");
                        }
                        Err(e) => {
                            error!(err = %e, "Failed to load default rules, attempting empty engine");
                            match Engine::load("") {
                                Ok(engine) => {
                                    map.insert(upstream.name.clone(), Arc::new(SharedWaf::new(engine, "empty".to_string())));
                                    warn!(upstream = %upstream.name, "Using empty rules as fallback");
                                }
                                Err(e) => {
                                    error!(err = %e, "Cannot create an empty engine. Upstream will be disabled.");
                                }
                            }
                        }
                    }
                }
            }
        }
        Arc::new(RwLock::new(map))
    }

    /// Global reload: reload each engine from its configured path in-place.
    async fn reload_all(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let cfg = &self.config;
        let mut guard = self.wafs.write().await;
        for upstream in &cfg.upstream {
            if let Some(waf) = guard.get_mut(&upstream.name) {
                let rules_path = format!("{}/rules/{}", env!("CARGO_MANIFEST_DIR"), upstream.waf_rules);
                if !std::path::Path::new(&rules_path).exists() {
                    warn!("Rules file does NOT exist: {}", rules_path);
                }
                match Engine::load(&rules_path) {
                    Ok(_engine) => {
                        if let Err(e) = waf.reload_now() {
                            let msg = format!("{}: reload error: {}", upstream.name, e);
                            errors.push(msg);
                        } else {
                            info!(upstream = %upstream.name, "Reloaded WAF rules successfully");
                        }
                    }
                    Err(e) => {
                        let msg = format!("{}: failed to load rules {}: {}", upstream.name, rules_path, e);
                        warn!(%msg, "Reload failed for upstream");
                        errors.push(msg);
                    }
                }
            } else {
                warn!(upstream = %upstream.name, "No WAF present for this upstream during reload");
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Return the best matching upstream for a host (handles exact match and subdomain match properly)
    fn find_upstream<'a>(&'a self, host: &str) -> Option<&'a UpstreamConfig> {
        let host = host.trim().to_lowercase();
        // exact match
        if let Some(u) = self.config.upstream.iter().find(|u| u.sni.eq_ignore_ascii_case(&host)) {
            return Some(u);
        }
        // wildcard/subdomain match: upstream.sni might be "example.com" or "*.example.com"
        // consider host == example.com OR host ends with ".example.com"
        for u in &self.config.upstream {
            let sni = u.sni.to_lowercase();
            if sni.starts_with("*.") {
                let domain = &sni[2..];
                if host == domain || host.ends_with(&format!(".{}", domain)) {
                    return Some(u);
                }
            } else {
                if host == sni || host.ends_with(&format!(".{}", sni)) {
                    return Some(u);
                }
            }
        }
        // explicit default
        if let Some(u) = self.config.upstream.iter().find(|u| u.sni == "default") {
            return Some(u);
        }
        // fallback
        self.config.upstream.first()
    }

    /// convenient debug info
    async fn wafs_info(&self) -> String {
        let guard = self.wafs.read().await;
        let mut out = String::new();
        for (k, v) in guard.iter() {
            out.push_str(&format!("{}: {}\n", k, v.get_rules_info()));
        }
        out
    }
}

// Имя выбранного upstream
type UpstreamContext = Option<String>;

#[async_trait::async_trait]
impl ProxyHttp for AppState {
    // Используем свой тип контекста
    type CTX = UpstreamContext;

    fn new_ctx(&self) -> Self::CTX {
        None // Изначально контекст пустой
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> pingora::Result<Box<HttpPeer>> {
        // For routing we need host from the request headers which are available in session.
        // The Pingora API in this example doesn't provide full typed header access here, so
        // the real implementation should extract host from session earlier or pass it via ctx.
        // Keep this minimal: fallback to first upstream.
        info!("Selecting upstream from context: {:?}", ctx);
        if let Some(upstream_name) = ctx {
                let upstream = self.config.upstream
                    .iter()
                    .find(|u| &u.name == upstream_name);
                
                match upstream {
                    Some(u) => {
                        info!("Selected upstream: {} -> {}", upstream_name, u.address);
                        Ok(Box::new(HttpPeer::new(
                            u.address.clone(),
                            u.use_tls,
                            u.sni.clone()
                        )))
                    }
                    None => {
                        error!("Upstream '{}' not found in config", upstream_name);
                        // Возвращаем первый upstream как fallback
                        let fallback = self.config.upstream.first()
                            .expect("No upstreams configured");
                        Ok(Box::new(HttpPeer::new(
                            fallback.address.clone(),
                            fallback.use_tls,
                            fallback.sni.clone()
                        )))
                    }
                }
            } else {
                error!("No upstream selected in context, using first upstream");
                let upstream = self.config.upstream.first()
                    .expect("No upstreams configured");
                Ok(Box::new(HttpPeer::new(
                    upstream.address.clone(),
                    upstream.use_tls,
                    upstream.sni.clone()
                )))
            }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> pingora::Result<bool> {
        let headers = session.req_header();
        let host_header = headers
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_lowercase();

        // Находим upstream по хосту
        let upstream = match self.find_upstream(&host_header) {
            Some(u) => u,
            None => {
                warn!(host = %host_header, "No upstream found, responding 404");
                session.respond_error(404).await?;
                return Ok(true);
            }
        };

        // Сохраняем имя upstream в контекст для использования в upstream_peer
        *ctx = Some(upstream.name.clone());

        // Pingora’s version enum → convert to HTTP/x.x
        let version = match headers.version {
            pingora::http::Version::HTTP_10 => "HTTP/1.0",
            pingora::http::Version::HTTP_11 => "HTTP/1.1",
            pingora::http::Version::HTTP_2 => "HTTP/2",
            _ => "HTTP/1.1", // fallback
        };

        //let request_line = format!("{} {} {}", method, uri, version);

        // find upstream
        let upstream = match self.find_upstream(&host_header) {
            Some(u) => u,
            None => {
                warn!(host = %host_header, "No upstream found, responding 404");
                session.respond_error(404).await?;
                return Ok(true);
            }
        };

        // read waf map reference
        let wafs_guard = self.wafs.read().await;
        let waf = match wafs_guard.get(&upstream.name) {
            Some(w) => w.clone(),
            None => {
                error!(upstream = %upstream.name, "No WAF configured, responding 500");
                session.respond_error(500).await?;
                return Ok(true);
            }
        };

        let client_ip = session.client_addr().map(|a| a.to_string()).unwrap_or_else(|| "unknown".into());
        let method = headers.method.as_str();
        let uri = headers.uri.to_string();
        let request_line = format!("{} {} {}", method, uri, version);
        
        // A more complete check would pass body, args, cookies etc.
        let waf_result = waf.check_detailed(&request_line, &headers.headers, &uri);

        info!(upstream = %upstream.name, method = %method, uri = %uri, client = %client_ip, "WAF check");

        if !waf_result.allowed {
            warn!(upstream = %upstream.name, rule_id = waf_result.rule_id, msg = waf_result.msg.as_deref().unwrap_or(""), "Blocked by WAF: {}", waf_result.reason);
            session.respond_error(403).await?;
            return Ok(true);
        }

        Ok(false)
    }
}

fn main() -> anyhow::Result<()> {
    // Инициализация логирования
    tracing_subscriber::fmt::init();

    // Загружаем конфиг
    let cfg = match Config::load_from() {
        Ok(c) => c,
        Err(e) => {
            error!("❌ Failed to load config.toml: {}", e);
            std::process::exit(1);
        }
    };
    info!("Loaded config: {:?}", cfg);

    // Создаём runtime для async инициализации WAF и Admin сервера
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let state = rt.block_on(async {
        let wafs = AppState::load_wafs(&cfg).await;
        AppState { config: cfg.clone(), wafs }
    });

    // Запуск Pingora (он создаёт свой runtime внутри)
    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy_service = http_proxy_service(&server.configuration, state.clone());
    let proxy_addr = format!("0.0.0.0:{}", state.config.server.proxy_port);
    proxy_service.add_tcp(&proxy_addr);
    server.add_service(proxy_service);

    info!("Proxy listening on http://{}", proxy_addr);

    // Spawn admin server in a separate task
    let admin_state = state.clone();
    let admin_addr = SocketAddr::from(([127,0,0,1], cfg.server.admin_port));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use hyper::{Body, Request, Response, Server as HyperServer};
            use hyper::service::{make_service_fn, service_fn};

            let make_svc = make_service_fn(move |_conn| {
                let s = admin_state.clone();
                async move {
                    Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                        let s = s.clone();
                        async move {
                            match req.uri().path() {
                                "/reload" => {
                                    match s.reload_all().await {
                                        Ok(_) => Ok::<_, hyper::Error>(Response::new(Body::from("Reload OK"))),
                                        Err(errs) => Ok(Response::builder()
                                            .status(500)
                                            .body(Body::from(format!("Reload errors: {:?}", errs)))
                                            .unwrap()),
                                    }
                                }
                                "/stats" => {
                                    let body = s.wafs_info().await;
                                    Ok::<_, hyper::Error>(Response::new(Body::from(body)))
                                }
                                "/health" => Ok(Response::new(Body::from("OK"))),
                                _ => Ok(Response::builder()
                                    .status(404)
                                    .body(Body::from("Not found"))
                                    .unwrap()),
                            }
                        }
                    }))
                }
            });

            let server = HyperServer::bind(&admin_addr).serve(make_svc);
            info!("Admin API listening on http://{}", admin_addr);
            if let Err(e) = server.await {
                error!(err = %e, "Admin server error");
            }
        });
    });

    server.run_forever(); // Pingora запускает свой runtime
}

