use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server as HyperServer};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, error};
use crate::proxy::proxy_manager::ProxyManager;
//use crate::config::config::Config;

pub async fn run_admin_server(port: u16, proxy_manager: Arc<ProxyManager>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    
    let make_svc = make_service_fn(move |_conn| {
        let proxy_manager = proxy_manager.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let proxy_manager = proxy_manager.clone();
                async move {
                    match req.uri().path() {
                        "/reload" => {
                            match proxy_manager.reload_all_rules() {
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
                            let rules_info = proxy_manager.get_all_rules_info();
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
                        "/info" => {
                            let info = proxy_manager.get_waf_info();
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .body(Body::from(info))
                                    .unwrap(),
                            )
                        }
                        path if path.starts_with("/server/") => {
                            let server_name = path.strip_prefix("/server/").unwrap_or("");
                            if server_name.is_empty() {
                                // Список всех серверов при запросе /server
                                let servers = proxy_manager.get_server_list();
                                let response = servers.join("\n");
                                Ok(Response::builder()
                                    .status(200)
                                    .body(Body::from(response))
                                    .unwrap())
                            } else if let Some(info) = proxy_manager.get_server_info(server_name) {
                                Ok(Response::builder()
                                    .status(200)
                                    .body(Body::from(info))
                                    .unwrap())
                            } else {
                                Ok(Response::builder()
                                    .status(404)
                                    .body(Body::from(format!("Server '{}' not found", server_name)))
                                    .unwrap())
                            }
                        }
                        // "/server/reload" => {
                        //     if req.method() == hyper::Method::POST {
                        //         // Перезагрузка конфигурации из файла
                        //         let new_config = Config::load();
                        //         match proxy_manager.reload_config(new_config).await {
                        //             Ok(_) => Ok(Response::builder()
                        //                 .status(200)
                        //                 .body(Body::from("Configuration reloaded successfully"))
                        //                 .unwrap()),
                        //             Err(e) => Ok(Response::builder()
                        //                 .status(500)
                        //                 .body(Body::from(format!("❌ Config reload failed: {e}")))
                        //                 .unwrap()),
                        //         }
                        //     } else {
                        //         Ok(Response::builder()
                        //             .status(405)
                        //             .body(Body::from("Method not allowed"))
                        //             .unwrap())
                        //     }
                        // }
                        _ => {
                            Ok(Response::builder()
                                .status(404)
                                .body(Body::from("❌ Endpoint not found. Available: /reload, /stats, /health, /info, /server/{name}"))
                                .unwrap())
                        }
                    }
                }
            }))
        }
    });

    let server = HyperServer::bind(&addr).serve(make_svc);

    info!(address = %addr, "Admin API started");
    info!("Available endpoints: /reload, /stats, /health, /info, /server/");

    if let Err(e) = server.await {
        error!(error = %e, "Admin server error");
    }
}