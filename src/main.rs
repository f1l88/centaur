use pingora::server::Server;
//use pingora::server::configuration::ServerConf;
use pingora::proxy::{ProxyHttp, Session, http_proxy_service};
use pingora::upstreams::peer::HttpPeer;

use std::net::SocketAddr;
use std::sync::Arc;
use crate::waf::Engine;
use crate::waf::reloader::SharedWaf;

use serde::Deserialize;

mod waf;

struct MyProxy {
    waf: Arc<SharedWaf>,
    config: Config,
}

#[derive(Deserialize)]
struct Config {
    server: ServerConfig,
    upstream: UpstreamConfig,
}

#[derive(Deserialize)]
struct ServerConfig {
    proxy_port: u16,
}

#[derive(Deserialize, Clone)]
struct UpstreamConfig {
    address: String,
    use_tls: bool,
    sni: String,
}

impl Config {
    fn load() -> Self {
        let config_str = std::fs::read_to_string("config.toml")
            .expect("Failed to read config.toml");
        toml::from_str(&config_str)
            .expect("Failed to parse config.toml")
    }
}

// ⭐ ДОБАВЬТЕ ЭТУ РЕАЛИЗАЦИЮ
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

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> pingora::Result<Box<HttpPeer>> {
        let peer = HttpPeer::new(
            self.config.upstream.address.clone(),
            self.config.upstream.use_tls,
            self.config.upstream.sni.clone(), // клонируем sni
        );
        Ok(Box::new(peer))
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> pingora::Result<bool> {
        let headers = &session.req_header().headers;
        
        let allowed = {
            let waf_guard = self.waf.inner.read().expect("WAF lock poisoned");
            waf_guard.check(&headers)
        };
        
        if !allowed {
            session.respond_error(403).await?;
            return Ok(true);
        }
        Ok(false)
    }
}

fn main() {
    // Загружаем конфигурацию
    let config = Config::load();
    // Убираем async и используем блокирующую версию для загрузки WAF
    let rules_path = "rules/example.conf";
    let engine = Engine::load(rules_path).expect("Failed to load rules");
    let shared_waf = Arc::new(SharedWaf::new(engine, rules_path));

    // Запускаем SIGHUP watcher в отдельном потоке (не async)
    let sighup_waf = shared_waf.clone();
    std::thread::spawn(move || {
        // Если watch_sighup асинхронный, создаем отдельный runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            <SharedWaf as Clone>::clone(&sighup_waf).watch_sighup().await;
        });
    });

    // Start Pingora Proxy
    let mut server = Server::new(None).expect("Failed to create server");

    server.bootstrap();

    // Создаем прокси сервис
    let mut proxy_service = http_proxy_service(
        &server.configuration, 
        MyProxy::from_config(shared_waf.clone())
    );
    // Создаем прокси сервис и ЯВНО указываем порт
    //let mut proxy_service = http_proxy_service(&server.configuration, MyProxy { waf: shared_waf.clone(), config: from_config() });
    //proxy_service.add_tcp("127.0.0.1:6188"); // ← ДОБАВЬТЕ ЭТУ СТРОКУ

    // Используем порт из конфига
    // Используем порт из конфига
    let proxy_addr = format!("127.0.0.1:{}", config.server.proxy_port);
    proxy_service.add_tcp(&proxy_addr);

    server.add_service(proxy_service);

    //server.add_service(http_proxy_service(&server.configuration, MyProxy { waf: shared_waf.clone() }));

    // Запускаем HTTP admin server в отдельном потоке
    let reload_waf = shared_waf.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use hyper::{Body, Request, Response, Server as HyperServer};
            use hyper::service::{make_service_fn, service_fn};

            let make_svc = make_service_fn(move |_conn| {
                let waf = reload_waf.clone();
                async move {
                    Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                        let waf = waf.clone();
                        async move {
                            if req.uri().path() == "/reload" {
                                match waf.reload_now() {
                                    Ok(_) => Ok::<_, hyper::Error>(Response::builder()
                                        .status(200)
                                        .body(Body::from("Reloaded successfully"))
                                        .unwrap()),
                                    Err(e) => Ok(Response::builder()
                                        .status(500)
                                        .body(Body::from(format!("Reload failed: {e}")))
                                        .unwrap()),
                                }
                            } else {
                                Ok(Response::builder()
                                    .status(404)
                                    .body(Body::from("Not Found"))
                                    .unwrap())
                            }
                        }
                    }))
                }
            });

            let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
            let server = HyperServer::bind(&addr).serve(make_svc);

            println!("Admin API listening on http://{}", addr);
            if let Err(e) = server.await {
                eprintln!("Admin server error: {}", e);
            }
        });
    });

    println!("Proxy server starting...");
    server.run_forever();
}