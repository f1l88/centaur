use std::sync::Arc;
use std::collections::HashMap;

//use pingora::server::Server;
//use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::http::HMap;
use pingora::Result;

use crate::waf::reloader::SharedWaf;
use crate::waf::Engine;
use crate::config::config::{Config, UpstreamConfig};
use crate::web::api::run_admin_server;

use bytes::Bytes;
use parking_lot::Mutex;
use chrono::Utc;

use tracing::{debug, error, info, warn, instrument};

//use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct WafViolation {
    pub rule_id: u32,
    pub reason: String,
    pub blocked: bool,
    pub timestamp: chrono::DateTime<Utc>,
    pub source: String, // "header" или "body"
}

// Структура для BodyInspector
pub struct BodyInspector {
    pub max_body_size: usize,
    pub buffer: Arc<Mutex<Vec<u8>>>,
    pub enabled: bool,
}

impl BodyInspector {
    pub fn new(max_body_size: usize, enabled: bool) -> Self {
        Self {
            max_body_size,
            buffer: Arc::new(Mutex::new(Vec::new())),
            enabled,
        }
    }

    pub fn append_chunk(&self, chunk: &Bytes) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let mut buffer = self.buffer.lock();

        if buffer.len() + chunk.len() > self.max_body_size {
            return Err(pingora::Error::because(
                pingora::ErrorType::InvalidHTTPHeader,
                format!(
                    "Request body exceeds maximum size of {} bytes",
                    self.max_body_size
                ),
                pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader),
            ));
        }

        buffer.extend_from_slice(chunk);
        Ok(())
    }

    pub fn get_body(&self) -> Vec<u8> {
        self.buffer.lock().clone()
    }

    pub fn clear(&self) {
        self.buffer.lock().clear();
    }
}

// Структура для хранения состояния запроса
pub struct RequestContext {
    pub body_inspector: BodyInspector,
    pub upstream_name: Option<String>,
    pub upstream_key: Option<String>,
    pub client_ip: String,
    pub violations: Vec<WafViolation>,
}

impl RequestContext {
    pub fn new(client_ip: &str) -> Self {
        Self {
            body_inspector: BodyInspector::new(10 * 1024 * 1024, true), // 10MB по умолчанию
            upstream_name: None,
            upstream_key: None,
            client_ip: client_ip.to_string(),
            violations: Vec::new(),
        }
    }
}

pub struct ProxyManager {
    pub proxies: HashMap<String, Arc<MyProxy>>,
    pub config: Config,
}

impl ProxyManager {
    pub fn new(config: Config) -> Self {
        let mut proxies = HashMap::new();
        
        for server_name in config.get_servers().keys() {
            let proxy = MyProxy::new_for_server(config.clone(), server_name);
            proxies.insert(server_name.clone(), Arc::new(proxy));
        }
        
        Self { proxies, config }
    }
    
    pub fn get_proxy(&self, server_name: &str) -> Option<Arc<MyProxy>> {
        self.proxies.get(server_name).cloned()
    }

    pub fn get_server_list(&self) -> Vec<String> {
        self.proxies.keys().cloned().collect()
    }
        
    pub fn reload_all_rules(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        
        for (name, proxy) in &self.proxies {
            if let Err(e) = proxy.reload_all_rules() {
                errors.push(format!("Failed to reload rules for {}: {}", name, e));
            }
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn get_all_rules_info(&self) -> String {
        let mut info = String::new();
        for (server_name, proxy) in &self.proxies {
            info.push_str(&format!("=== Server: {} ===\n", server_name));
            info.push_str(&proxy.get_all_rules_info());
            info.push_str("\n");
        }
        info
    }

    // Добавим метод для получения информации о WAF (просто обертка для первого прокси)
    pub fn get_waf_info(&self) -> String {
        if let Some((first_name, first_proxy)) = self.proxies.iter().next() {
            format!("Proxy Manager - First server '{}': {}", first_name, first_proxy.get_waf_info())
        } else {
            "No proxies available".to_string()
        }
    }
        
    pub fn get_server_info(&self, server_name: &str) -> Option<String> {
        self.proxies.get(server_name)
        .map(|proxy| proxy.get_waf_info())
    }
}


pub(crate) struct MyProxy {
    waf_engines: HashMap<String, Arc<SharedWaf>>,
    config: Config,
    server_name: String,
}

impl MyProxy {
    #[instrument(name = "MyProxy::new_for_server")]
    pub fn new_for_server(config: Config, server_name: &str) -> Self {
        let server = config.get_server(server_name)
            .unwrap_or_else(|| panic!("Server '{}' not found in config", server_name));

        let mut waf_engines = HashMap::new();

        info!("Loading WAF rules for each upstream");

        for upstream_key in &server.upstreams {
            let upstream = config.get_upstream(upstream_key)
                .unwrap_or_else(|| panic!("Upstream '{}' not found in config", upstream_key));
            
            let rules_path = format!(
                "{}/rules/{}/crs-setup.conf", 
                env!("CARGO_MANIFEST_DIR"),
                upstream.waf_rules
            );
            
            match Engine::load(&rules_path) {
                Ok(engine) => {
                    let shared_waf = Arc::new(SharedWaf::new(engine, rules_path.clone()));
                    waf_engines.insert(upstream_key.clone(), shared_waf);
                    info!(upstream = %upstream_key, rules = %upstream.waf_rules, "WAF rules loaded successfully");
                }
                Err(e) => {
                    error!(upstream = %upstream_key, rules = %upstream.waf_rules, error = %e, "Failed to load WAF rules");
                    let default_path = format!("{}/rules/default/default.conf", env!("CARGO_MANIFEST_DIR"));
                    match Engine::load(&default_path) {
                        Ok(engine) => {
                            let shared_waf = Arc::new(SharedWaf::new(engine, default_path));
                            waf_engines.insert(upstream_key.clone(), shared_waf);
                            warn!(upstream = %upstream_key, "Using default rules");
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to load default rules");
                            match Engine::load("") {
                                Ok(engine) => {
                                    let shared_waf = Arc::new(SharedWaf::new(engine, "empty".to_string()));
                                    waf_engines.insert(upstream_key.clone(), shared_waf);
                                    warn!(upstream = %upstream_key, "Using empty rules as fallback");
                                }
                                Err(e) => {
                                    error!(error = %e, "Failed to create empty engine");
                                    panic!("Cannot continue without WAF engine");
                                }
                            }
                        }
                    }
                }
            }
        }

        Self { 
            waf_engines, 
            config,
            server_name: server_name.to_string(),
        }
    }

    // Метод для получения upstream по хосту
    // fn get_upstream_for_host(&self, host: &str) -> Option<&UpstreamConfig> {
    //     let server = self.config.get_server(&self.server_name)?;
        
    //     for upstream_key in &server.upstreams {
    //         if let Some(upstream) = self.config.get_upstream(upstream_key) {
    //             if host.to_lowercase() == upstream.sni.to_lowercase() {
    //                 return Some(upstream);
    //             }
    //             if host.contains(&upstream.sni.to_lowercase()) {
    //                 return Some(upstream);
    //             }
    //         }
    //     }
        
    //     None
    // }

    fn get_upstream_key_and_config_for_host(&self, host: &str) -> Option<(&String, &UpstreamConfig)> {
        let server = self.config.get_server(&self.server_name)?;
        
        for upstream_key in &server.upstreams {
            if let Some(upstream) = self.config.get_upstream(upstream_key) {
                if host.to_lowercase() == upstream.sni.to_lowercase() {
                    return Some((upstream_key, upstream));
                }
                if host.contains(&upstream.sni.to_lowercase()) {
                    return Some((upstream_key, upstream));
                }
            }
        }
        
        None
    }

    // Остальные методы остаются прежними, но используем новую структуру
    pub fn get_waf_info(&self) -> String {
        let mut info = String::from(format!("WAF Engines for server '{}': ", self.server_name));
        let mut first = true;
        
        for (upstream_name, waf) in &self.waf_engines {
            let rules_info = waf.get_rules_info();
            let main_info = rules_info.lines().next().unwrap_or("").trim();
            
            if !first {
                info.push_str(", ");
            }
            info.push_str(&format!("{}: {}", upstream_name, main_info));
            first = false;
            
            debug!(
                upstream = %upstream_name,
                path = %waf.path.display(),
                "WAF engine"
            );
        }
        
        info
    }

    pub async fn watch_all_sighup(&self) {
        let mut handles = vec![];
        for (name, waf) in &self.waf_engines {
            let waf_clone = waf.clone();
            let name_clone = name.clone();
            let handle = tokio::spawn(async move {
                info!("Watching SIGHUP for {}", name_clone);
                waf_clone.watch_sighup().await;
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let _ = handle.await;
        }
    }

    pub fn reload_all_rules(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        
        for (name, waf) in &self.waf_engines {
            match waf.reload_now() {
                Ok(_) => info!("Successfully reloaded rules for {}", name),
                Err(e) => {
                    let error_msg = format!("Failed to reload rules for {}: {}", name, e);
                    errors.push(error_msg.clone());
                    println!("❌ {}", error_msg);
                }
            }
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn get_all_rules_info(&self) -> String {
        let mut info = String::new();
        for (name, waf) in &self.waf_engines {
            info.push_str(&format!("=== {} ===\n{}\n", name, waf.get_rules_info()));
        }
        info
    }
}

impl Clone for MyProxy {
    fn clone(&self) -> Self {
        let mut waf_engines = HashMap::new();
        for (name, waf) in &self.waf_engines {
            waf_engines.insert(name.clone(), waf.clone());
        }
        
        Self {
            waf_engines,
            config: self.config.clone(),
            server_name: self.server_name.clone(),
        }
    }
}

#[async_trait::async_trait]
impl ProxyHttp for MyProxy {
    type CTX = Option<RequestContext>; // ВАЖНО: Изменено на Option<RequestContext>

    fn new_ctx(&self) -> Self::CTX {
        None // Инициализируем как None
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let host_header = session
            .req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        // В upstream_peer использовать новый метод:
        let (upstream_key, upstream) = self.get_upstream_key_and_config_for_host(&host_header)
            .expect("No upstream configured for this host");

        if let Some(ctx) = ctx {
            ctx.upstream_name = Some(upstream_key.clone());
        }

        debug!(
            server = %self.server_name,
            upstream = %upstream_key,
            waf_rules = %upstream.waf_rules,
            "Routing request"
        );

        let backend_addr = upstream.addrs.first()
            .expect("No backend addresses configured");
            
        let peer = HttpPeer::new(
            backend_addr.clone(),
            upstream.use_tls,
            upstream.sni.clone(),
        );
        
        Ok(Box::new(peer))
    }

    #[instrument(
        skip(self, session, ctx),
        fields(
            host = ?session.req_header().headers.get("host"),
            method = ?session.req_header().method,
            uri = ?session.req_header().uri,
            client_addr = ?session.client_addr()
        )
    )]
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> pingora::Result<bool> {
        let request_headers = session.req_header();
        
        let client_ip = session
            .client_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        // Создаем новый контекст если его нет
        if ctx.is_none() {
            *ctx = Some(RequestContext::new(&client_ip));
        }
        
        let context = ctx.as_mut().unwrap();
        
        // Очищаем для нового запроса
        context.body_inspector.clear();
        context.violations.clear();
        
        let host_header = request_headers
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_lowercase();

        let (upstream_key, upstream) = match self.get_upstream_key_and_config_for_host(&host_header) {
            Some((key, upstream)) => (key, upstream),
            None => {
                warn!(host = %host_header, "Unknown upstream for host");
                session.respond_error(404).await?;
                return Ok(true);
            }
        };

        // Сохраняем ключ
        context.upstream_name = Some(upstream_key.clone());

        let waf = match self.waf_engines.get(upstream_key) {
            Some(waf) => waf,
            None => {
                error!(upstream = %upstream_key, "No WAF configured for upstream");
                session.respond_error(500).await?;
                return Ok(true);
            }
        };

        let method = request_headers.method.as_str();
        let uri = request_headers.uri.to_string();

        let mut headers_map = HMap::new();
        for (name, value) in request_headers.headers.iter() {
            headers_map.insert(name.clone(), value.clone());
        }

        let waf_result = waf.check_detailed(&headers_map, &uri, &method, None);

        debug!(
            upstream = %upstream_key,
            method = %method,
            uri = %uri,
            client_ip = %client_ip,
            "WAF header check"
        );

        if !waf_result.allowed {
            warn!(
                upstream = %upstream_key,
                method = %method,
                uri = %uri,
                rule_id = %waf_result.rule_id,
                reason = %waf_result.reason,
                "WAF blocked request (headers/URI)"
            );
            
            context.violations.push(WafViolation {
                rule_id: waf_result.rule_id,
                reason: waf_result.reason.clone(),
                blocked: true,
                timestamp: Utc::now(),
                source: "header".to_string(),
            });
            
            session.respond_error(403).await?;
            return Ok(true);
        }

        debug!(
            upstream = %upstream_key,
            method = %method,
            uri = %uri,
            "Request headers passed WAF check"
        );
        
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        let context = match ctx {
            Some(ctx) => ctx,
            None => {
                warn!("No context for body inspection");
                return Ok(());
            }
        };

        let upstream_name = match &context.upstream_name {
            Some(name) => name,
            None => {
                warn!("No upstream determined for body inspection");
                return Ok(());
            }
        };

        let waf = match self.waf_engines.get(upstream_name) {
            Some(waf) => waf,
            None => {
                error!(upstream = %upstream_name, "No WAF configured for body inspection");
                return Ok(());
            }
        };

        if let Some(chunk) = body {
            if let Err(e) = context.body_inspector.append_chunk(chunk) {
                error!(
                    upstream = %upstream_name,
                    client_ip = %context.client_ip,
                    "Body size limit exceeded: {}", e
                );
                
                context.violations.push(WafViolation {
                    rule_id: 413,
                    reason: format!("Body size limit exceeded: {}", e),
                    blocked: true,
                    timestamp: Utc::now(),
                    source: "body".to_string(),
                });
                
                session.respond_error(413).await?;
                return Err(pingora::Error::new_str("Body size limit exceeded"));
            }
        }

        if end_of_stream {
            let full_body = context.body_inspector.get_body();
            
            if !full_body.is_empty() {
                let request_headers = session.req_header();
                let method = request_headers.method.as_str();
                let uri = request_headers.uri.to_string();

                let mut headers_map = HMap::new();
                for (name, value) in request_headers.headers.iter() {
                    headers_map.insert(name.clone(), value.clone());
                }

                let waf_result = waf.check_detailed(
                    &headers_map, 
                    &uri, 
                    &method, 
                    Some(&full_body)
                );

                debug!(
                    upstream = %upstream_name,
                    method = %method,
                    uri = %uri,
                    client_ip = %context.client_ip,
                    body_size = full_body.len(),
                    "WAF body check"
                );

                if !waf_result.allowed {
                    warn!(
                        upstream = %upstream_name,
                        method = %method,
                        uri = %uri,
                        client_ip = %context.client_ip,
                        body_size = full_body.len(),
                        rule_id = %waf_result.rule_id,
                        reason = %waf_result.reason,
                        "WAF blocked request body"
                    );
                    
                    context.violations.push(WafViolation {
                        rule_id: waf_result.rule_id,
                        reason: waf_result.reason.clone(),
                        blocked: true,
                        timestamp: Utc::now(),
                        source: "body".to_string(),
                    });
                    
                    *body = None;

                    // помечаем downstream как завершённый
                    session.as_downstream();

                    // отправляем статус
                    session.respond_error(403).await?;
                    return Ok(());
                    //return Err(pingora::Error::new_str("WAF violation in request body"));
                }

                debug!(
                    upstream = %upstream_name,
                    method = %method,
                    uri = %uri,
                    body_size = full_body.len(),
                    "Request body passed WAF check"
                );
            } else {
                debug!(
                    upstream = %upstream_name,
                    client_ip = %context.client_ip,
                    "Empty request body, skipping WAF check"
                );
            }
        }

        Ok(())
    }
}

pub fn run_server(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let mut server_threads = vec![];
    
    // Создаем менеджер прокси
    let proxy_manager = Arc::new(ProxyManager::new(config.clone()));
    
    for (server_name, server_config) in config.get_servers() {
        let proxy_manager_clone = proxy_manager.clone();
        let server_name_clone = server_name.clone();
        let server_config_addr = server_config.addr.clone(); // Клонируем addr
        
        let thread = std::thread::spawn(move || {
            // Получаем прокси из менеджера
            let proxy = proxy_manager_clone.get_proxy(&server_name_clone)
                .expect(&format!("Proxy not found for server: {}", server_name_clone));
            
            info!("Starting server '{}' on {}", server_name_clone, server_config_addr);
            info!("{}", proxy.get_waf_info());
            
            // Клонируем переменные для внутреннего потока
            let sighup_proxy = proxy.clone();
            let server_name_for_sighup = server_name_clone.clone();
            
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    info!("Starting SIGHUP watcher for server '{}'", server_name_for_sighup);
                    sighup_proxy.watch_all_sighup().await;
                });
            });

            let mut server = pingora::server::Server::new(None).expect("Failed to create server");
            server.bootstrap();

            let mut proxy_service = pingora::proxy::http_proxy_service(
                &server.configuration,
                proxy.as_ref().clone(),
            );

            proxy_service.add_tcp(&server_config_addr);
            server.add_service(proxy_service);

            info!(address = %server_config_addr, "Proxy server '{}' started", server_name_clone);
            server.run_forever();
        });
        
        server_threads.push(thread);
    }

    let admin_port = config.get_admin_port();
    
    // Запускаем admin сервер
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            run_admin_server(admin_port, proxy_manager).await;
        });
    });

    info!("All proxy servers running");
    
    for thread in server_threads {
        let _ = thread.join();
    }
    
    Ok(())
}