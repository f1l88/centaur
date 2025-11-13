use pingora::server::Server;
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use centaur_core::waf::reloader::SharedWaf;
use centaur_core::waf::Engine;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;

use serde::Deserialize;

struct MyProxy {
    waf_engines: HashMap<String, Arc<SharedWaf>>, // upstream_name -> WAF
    config: Config,
}

#[derive(Deserialize, Clone)]
struct Config {
    server: ServerConfig,
    upstream: Vec<UpstreamConfig>,
}

#[derive(Deserialize, Clone)]
struct ServerConfig {
    proxy_port: u16,
}

#[derive(Deserialize, Clone)]
struct UpstreamConfig {
    name: String,
    address: String,
    use_tls: bool,
    sni: String,
    waf_rules: String,
    waf_mode: String,
}

impl Config {
    fn load() -> Self {
        let config_path = format!("{}/config.toml", env!("CARGO_MANIFEST_DIR"));
        let config_str = std::fs::read_to_string(&config_path)
            .expect("Failed to read config.toml");
        toml::from_str(&config_str).expect("Failed to parse config.toml")
    }
}

impl MyProxy {
    fn from_config() -> Self {
        let config = Config::load();
        let mut waf_engines = HashMap::new();

        println!("🛡️  Loading WAF rules for each upstream...");

        for upstream in &config.upstream {
            let rules_path = format!(
                "{}/rules/{}", 
                env!("CARGO_MANIFEST_DIR"),
                upstream.waf_rules
            );
            
            match Engine::load(&rules_path) {
                Ok(engine) => {
                    let shared_waf = Arc::new(SharedWaf::new(engine, rules_path.clone()));
                    waf_engines.insert(upstream.name.clone(), shared_waf);
                    println!("   ✅ {}: {} ({})", upstream.name, upstream.waf_rules, upstream.waf_mode);
                }
                Err(e) => {
                    println!("   ❌ {}: Failed to load {} - {}", upstream.name, upstream.waf_rules, e);
                    // Используем дефолтные правила
                    let default_path = format!("{}/rules/default.conf", env!("CARGO_MANIFEST_DIR"));
                    match Engine::load(&default_path) {
                        Ok(engine) => {
                            let shared_waf = Arc::new(SharedWaf::new(engine, default_path));
                            waf_engines.insert(upstream.name.clone(), shared_waf);
                            println!("   ✅ {}: Using default rules", upstream.name);
                        }
                        Err(e) => {
                            eprintln!("   💥 Failed to load default rules: {}", e);
                            // Создаем пустой движок через загрузку пустых правил
                            match Engine::load("") {
                                Ok(engine) => {
                                    let shared_waf = Arc::new(SharedWaf::new(engine, "empty".to_string()));
                                    waf_engines.insert(upstream.name.clone(), shared_waf);
                                    println!("   ⚠️  {}: Using empty rules as fallback", upstream.name);
                                }
                                Err(e) => {
                                    eprintln!("   💥 Failed to create empty engine: {}", e);
                                    panic!("Cannot continue without WAF engine");
                                }
                            }
                        }
                    }
                }
            }
        }

        Self { waf_engines, config }
    }

    fn get_upstream_for_host(&self, host: &str) -> Option<&UpstreamConfig> {
        self.config
            .upstream
            .iter()
            .find(|u| host == u.sni.to_lowercase())
            .or_else(|| {
                self.config
                    .upstream
                    .iter()
                    .find(|u| host.contains(&u.sni.to_lowercase()))
            })
            .or_else(|| self.config.upstream.iter().find(|u| u.sni == "default"))
            .or_else(|| self.config.upstream.first())
    }

    pub fn get_waf_info(&self) -> String {
        let mut info = String::from("🛡️ WAF Engines Loaded:\n");
        for (upstream_name, waf) in &self.waf_engines {
            info.push_str(&format!("   • {}: {}\n", upstream_name, waf.get_rules_info()));
        }
        info
    }

    pub async fn watch_all_sighup(&self) {
        let mut handles = vec![];
        for (name, waf) in &self.waf_engines {
            let waf_clone = waf.clone();
            let name_clone = name.clone();
            let handle = tokio::spawn(async move {
                println!("👀 Watching SIGHUP for {}", name_clone);
                waf_clone.watch_sighup().await;
            });
            handles.push(handle);
        }
        
        // Ждем завершения всех задач
        for handle in handles {
            let _ = handle.await;
        }
    }

    pub fn reload_all_rules(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        
        for (name, waf) in &self.waf_engines {
            match waf.reload_now() {
                Ok(_) => println!("✅ Successfully reloaded rules for {}", name),
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
        }
    }
}

#[async_trait::async_trait]
impl ProxyHttp for MyProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let host_header = session
            .req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let upstream = self.get_upstream_for_host(&host_header)
            .expect("No upstream configured");

        println!(
            "   🔀 Маршрутизация: {} -> {} (WAF: {})",
            host_header, upstream.name, upstream.waf_rules
        );

        let peer = HttpPeer::new(
            upstream.address.clone(),
            upstream.use_tls,
            upstream.sni.clone(),
        );
        Ok(Box::new(peer))
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        let headers = session.req_header();

        let host_header = headers
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_lowercase();

        // Находим upstream и соответствующий WAF
        let upstream = match self.get_upstream_for_host(&host_header) {
            Some(upstream) => upstream,
            None => {
                println!("❌ Unknown upstream for host: {}", host_header);
                session.respond_error(404).await?;
                return Ok(true);
            }
        };

        let waf = match self.waf_engines.get(&upstream.name) {
            Some(waf) => waf,
            None => {
                println!("❌ No WAF configured for upstream: {}", upstream.name);
                session.respond_error(500).await?;
                return Ok(true);
            }
        };

        let client_ip = session
            .client_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let method = headers.method.as_str();
        let uri = headers.uri.to_string();

        // Проверка WAF с указанием upstream
        let waf_result = waf.check_detailed(&headers.headers, &uri);

        println!(
            "🛡️  WAF проверка [{}]: {} {} от {}",
            upstream.name, method, uri, client_ip
        );
        println!("   📋 Правила: {}, Режим: {}", upstream.waf_rules, upstream.waf_mode);
        println!(
            "   Статус: {}",
            if waf_result.allowed {
                "✅ РАЗРЕШЕНО"
            } else {
                "❌ ЗАБЛОКИРОВАНО"
            }
        );

        if !waf_result.allowed {
            println!(
                "❌ WAF БЛОКИРОВКА [{}]: {} {} заблокирован по правилу ID {}",
                upstream.name, method, uri, waf_result.rule_id
            );
            println!("   📋 Причина: {}", waf_result.reason);
            
            if let Some(rule_message) = &waf_result.matched_rule {
                println!("   📝 Сообщение правила: {}", rule_message);
            }
            
            session.respond_error(403).await?;
            return Ok(true);
        }

        println!("✅ WAF РАЗРЕШЕНИЕ [{}]: {} {} пропущен", upstream.name, method, uri);
        println!("---");
        Ok(false)
    }
}

fn main() {
    let proxy = MyProxy::from_config();
    
    println!("{}", proxy.get_waf_info());
    println!("🔄 Настроено upstream серверов: {}", proxy.config.upstream.len());
    for upstream in &proxy.config.upstream {
        println!(
            "   • {} -> {} (TLS: {}, SNI: {})",
            upstream.name, upstream.address, upstream.use_tls, upstream.sni
        );
    }

    // Запускаем SIGHUP watcher для КАЖДОГО WAF движка
    let sighup_proxy = proxy.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            sighup_proxy.watch_all_sighup().await;
        });
    });

    // Start Pingora Proxy
    let mut server = Server::new(None).expect("Failed to create server");
    server.bootstrap();

    let mut proxy_service = http_proxy_service(
        &server.configuration,
        proxy.clone(),
    );

    let proxy_addr = format!("0.0.0.0:{}", proxy.config.server.proxy_port);
    proxy_service.add_tcp(&proxy_addr);
    server.add_service(proxy_service);

    println!("🚀 Proxy Pingora running on http://{}", proxy_addr);

    // Запускаем HTTP admin server в отдельном потоке
    let admin_proxy = proxy.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use hyper::service::{make_service_fn, service_fn};
            use hyper::{Body, Request, Response, Server as HyperServer};

            let make_svc = make_service_fn(move |_conn| {
                let proxy = admin_proxy.clone();
                async move {
                    Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                        let proxy = proxy.clone();
                        async move {
                            match req.uri().path() {
                                "/reload" => {
                                    match proxy.reload_all_rules() {
                                        Ok(_) => Ok::<_, hyper::Error>(
                                            Response::builder()
                                                .status(200)
                                                .body(Body::from("All WAF rules reloaded successfully"))
                                                .unwrap(),
                                        ),
                                        Err(e) => Ok(Response::builder()
                                            .status(500)
                                            .body(Body::from(format!("❌ Reload failed: {e}")))
                                            .unwrap()),
                                    }
                                }
                                "/stats" => {
                                    let rules_info = proxy.get_all_rules_info();
                                    Ok::<_, hyper::Error>(
                                        Response::builder()
                                            .status(200)
                                            .body(Body::from(rules_info))
                                            .unwrap(),
                                    )
                                }
                                "/health" => {
                                    Ok::<_, hyper::Error>(
                                        Response::builder()
                                            .status(200)
                                            .body(Body::from("WAF proxy is healthy"))
                                            .unwrap(),
                                    )
                                }
                                _ => {
                                    Ok(Response::builder()
                                        .status(404)
                                        .body(Body::from("❌ Endpoint not found. Available: /reload, /stats, /health"))
                                        .unwrap())
                                }
                            }
                        }
                    }))
                }
            });

            let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
            let server = HyperServer::bind(&addr).serve(make_svc);

            println!("🔧 Admin API listening on http://{}", addr);
            println!("   Available endpoints:");
            println!("   - GET /reload  - Reload all WAF rules");
            println!("   - GET /stats   - Show all rules statistics");
            println!("   - GET /health  - Health check");

            if let Err(e) = server.await {
                eprintln!("Admin server error: {}", e);
            }
        });
    });

    println!("🎯 Proxy server starting...");
    server.run_forever();
}