use tracing::info;
use crate::config::config;

pub fn init_tracing(config: &Option<config::TracingConfig>) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, fmt};
    
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            if let Some(cfg) = config {
                EnvFilter::new(&cfg.level)
            } else {
                EnvFilter::new("info")
            }
        });

    match config {
        Some(cfg) => {
            match cfg.output.as_str() {
                "json" => {
                    let json_layer = fmt::layer()
                        .json()
                        .with_ansi(cfg.enable_ansi);
                    
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(json_layer)
                        .init();
                }
                "file" => {
                    let file_appender = tracing_appender::rolling::daily("logs", "pingwaf.log");
                    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
                    
                    let file_layer = fmt::layer()
                        .with_writer(non_blocking)
                        .json();
                    
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(file_layer)
                        .init();
                }
                "both" => {
                    let console_layer = fmt::layer()
                        .with_ansi(cfg.enable_ansi);
                    
                    let file_appender = tracing_appender::rolling::daily("logs", "pingwaf.log");
                    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
                    
                    let file_layer = fmt::layer()
                        .with_writer(non_blocking)
                        .json();
                    
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(console_layer)
                        .with(file_layer)
                        .init();
                }
                _ => {
                    let console_layer = fmt::layer()
                        .with_ansi(cfg.enable_ansi);
                    
                    tracing_subscriber::registry()
                        .with(env_filter)
                        .with(console_layer)
                        .init();
                }
            }
        }
        None => {
            let console_layer = fmt::layer()
                .with_ansi(true);
            
            tracing_subscriber::registry()
                .with(env_filter)
                .with(console_layer)
                .init();
        }
    }
    
    info!("Tracing initialized");
}