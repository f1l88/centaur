use pingora::server::Server;
//use pingora::server::configuration::ServerConf;
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use centaur_core::waf::reloader::SharedWaf;
use centaur_core::waf::Engine;
use std::net::SocketAddr;
use std::sync::Arc;

use serde::Deserialize;

struct MyProxy {
    waf: Arc<SharedWaf>,
    config: Config,
}

#[derive(Deserialize)]
struct Config {
    server: ServerConfig,
    upstream: Vec<UpstreamConfig>,
}

#[derive(Deserialize)]
struct ServerConfig {
    proxy_port: u16,
}

#[derive(Deserialize, Clone)]
struct UpstreamConfig {
    name: String,
    address: String,
    use_tls: bool,
    sni: String,
}

impl Config {
    fn load() -> Self {
        let config_path = format!("{}/config.toml", env!("CARGO_MANIFEST_DIR"));
        let config_str = std::fs::read_to_string(&config_path)
            //let config_str = std::fs::read_to_string("../config.toml")
            .expect("Failed to read config.toml");
        toml::from_str(&config_str).expect("Failed to parse config.toml")
    }
}

impl MyProxy {
    fn from_config(waf: Arc<SharedWaf>) -> Self {
        let config = Config::load();
        Self { waf, config }
    }
}

#[async_trait::async_trait]
impl ProxyHttp for MyProxy {
    // объект для каждого запроса для передачи данных между обработчиками
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        // Получаем Host header
        let host_header = _session
            .req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        // Ищем upstream по точному совпадению имени
        let upstream = self
            .config
            .upstream
            .iter()
            .find(|u| host_header == u.name.to_lowercase())
            .or_else(|| {
                // Ищем по частичному совпадению (например: api.example.com -> api)
                self.config
                    .upstream
                    .iter()
                    .find(|u| host_header.contains(&u.name.to_lowercase()))
            })
            .or_else(|| {
                // Используем upstream с именем "default"
                self.config.upstream.iter().find(|u| u.name == "default")
            })
            .or_else(|| self.config.upstream.first())
            .expect("No upstream configured");

        println!(
            "   🔀 Маршрутизация: {} -> {} ({})",
            host_header, upstream.name, upstream.address
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

        let client_ip = session
            .client_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let method = headers.method.as_str();
        let uri = headers.uri.to_string();
        let host = headers
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");

        // Детальная проверка WAF
        let waf_result = self.waf.check_detailed(&headers.headers, &uri);

        // Детальное логирование WAF
        println!(
            "WAF проверка: {} {} (Host: {}) от {}",
            method, uri, host, client_ip
        );
        println!(
            "Статус: {}",
            if waf_result.allowed {
                "РАЗРЕШЕНО"
            } else {
                "ЗАБЛОКИРОВАНО"
            }
        );
        println!("   📋 Причина: {}", waf_result.reason);

        if let Some(rule) = &waf_result.matched_rule {
            println!("ID правила: {}", rule.id);
            println!("Переменная: {}", rule.variable);
            println!("Оператор: {}", rule.operator);
            println!("Аргумент: {}", rule.argument);

            // Логируем действия правила
            if !rule.actions.is_empty() {
                let actions: Vec<String> = rule.actions.keys().cloned().collect();
                println!("Действия: {}", actions.join(", "));
            }
        }

        if let Some(header_name) = &waf_result.header_name {
            if let Some(header_value) = &waf_result.header_value {
                // Обрезаем длинные значения для читаемости
                let display_value = if header_value.len() > 100 {
                    format!("{}...", &header_value[..100])
                } else {
                    header_value.clone()
                };
                println!("Заголовок: {} = \"{}\"", header_name, display_value);
            }
        }

        if !waf_result.allowed {
            println!(
                "WAF БЛОКИРОВКА: Запрос {} {} заблокирован по правилу ID {}",
                method, uri, waf_result.rule_id
            );
            session.respond_error(403).await?;
            return Ok(true);
        }

        println!("WAF РАЗРЕШЕНИЕ: {} {} пропущен", method, uri);
        println!("---"); // разделитель для читаемости
        Ok(false)
    }
}

fn main() {
    // Загружаем конфигурацию
    let config = Config::load();
    // Убираем async и используем блокирующую версию для загрузки WAF
    let rules_path = format!("{}/rules/example.conf", env!("CARGO_MANIFEST_DIR"));
    //let engine = load_rules_from_file(&rules_path)
    let engine = Engine::load(&rules_path).expect("Failed to load rules");
    let shared_waf = Arc::new(SharedWaf::new(engine, rules_path));

    // Выводим информацию о загруженных правилах и upstream'ах
    println!("{}", shared_waf.get_rules_info());
    println!("🔄 Настроено upstream серверов: {}", config.upstream.len());
    for upstream in &config.upstream {
        println!(
            "   • {} -> {} (TLS: {}, SNI: {})",
            upstream.name, upstream.address, upstream.use_tls, upstream.sni
        );
    }

    // Запускаем SIGHUP watcher в отдельном потоке (не async)
    let sighup_waf = shared_waf.clone();
    std::thread::spawn(move || {
        // Если watch_sighup асинхронный, создаем отдельный runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            <SharedWaf as Clone>::clone(&sighup_waf)
                .watch_sighup()
                .await;
        });
    });

    // Start Pingora Proxy
    let mut server = Server::new(None).expect("Failed to create server");

    server.bootstrap();

    // Создаем прокси сервис
    let mut proxy_service = http_proxy_service(
        &server.configuration,
        MyProxy::from_config(shared_waf.clone()),
    );

    // Используем порт из конфига
    let proxy_addr = format!("127.0.0.1:{}", config.server.proxy_port);
    proxy_service.add_tcp(&proxy_addr);
    server.add_service(proxy_service);

    println!("Proxy Pingora running on http://{}", proxy_addr);

    //server.add_service(http_proxy_service(&server.configuration, MyProxy { waf: shared_waf.clone() }));

    // Запускаем HTTP admin server в отдельном потоке
    let reload_waf = shared_waf.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use hyper::service::{make_service_fn, service_fn};
            use hyper::{Body, Request, Response, Server as HyperServer};

            let make_svc = make_service_fn(move |_conn| {
                let waf = reload_waf.clone();
                async move {
                    Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                        let waf = waf.clone();
                        async move {                            match req.uri().path() {
                            "/reload" => {
                                    match waf.reload_now() {
                                        Ok(_) => Ok::<_, hyper::Error>(
                                            Response::builder()
                                                .status(200)
                                                .body(Body::from("Rules reloaded successfully"))
                                                .unwrap(),
                                        ),
                                        Err(e) => Ok(Response::builder()
                                            .status(500)
                                            .body(Body::from(format!("❌ Reload failed: {e}")))
                                            .unwrap()),
                                    }
                                }
                                "/stats" => {
                                    let rules_info = waf.get_rules_info();
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
                                            .body(Body::from("WAF is healthy"))
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
            println!("   - GET /reload  - Reload WAF rules");
            println!("   - GET /stats   - Show rules statistics");
            println!("   - GET /health  - Health check");

            if let Err(e) = server.await {
                eprintln!("Admin server error: {}", e);
            }
        });
    });

    println!("Proxy server starting...");
    server.run_forever();
}
