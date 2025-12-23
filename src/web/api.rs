use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server as HyperServer};
use std::net::SocketAddr;
use tracing::{info, error};
use crate::proxy::proxy::MyProxy;

pub async fn run_admin_server(proxy: MyProxy, port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    
    let make_svc = make_service_fn(move |_conn| {
        let proxy = proxy.clone();
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
                        "/info" => {
                            let info = proxy.get_waf_info();
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .body(Body::from(info))
                                    .unwrap(),
                            )
                        }
                        _ => {
                            Ok(Response::builder()
                                .status(404)
                                .body(Body::from("❌ Endpoint not found. Available: /reload, /stats, /health, /info"))
                                .unwrap())
                        }
                    }
                }
            }))
        }
    });

    let server = HyperServer::bind(&addr).serve(make_svc);

    info!(address = %addr, "Admin API started");
    info!("Available endpoints: /reload, /stats, /health, /info");

    if let Err(e) = server.await {
        error!(error = %e, "Admin server error");
    }
}