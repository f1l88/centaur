use tracing::info;
use tracing_subscriber::Layer;
use crate::config::config;

pub fn init_tracing(
    config: &Option<config::TracingConfig>
) -> Vec<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::{
        layer::SubscriberExt,
        util::SubscriberInitExt,
        EnvFilter,
        fmt,
        filter::Targets,
    };
    use tracing_appender::non_blocking::NonBlocking;
    use std::fs::OpenOptions;
    use chrono::Local;

    let mut guards = Vec::new();

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            if let Some(cfg) = config {
                EnvFilter::new(&cfg.level)
            } else {
                EnvFilter::new("info")
            }
        });

    if let Some(cfg) = config {
        match cfg.output.as_str() {
            "file" | "both" => {
                //let date = Local::now().format("%Y-%m-%d");

                // =========================
                // Основной лог (всё, кроме атак)
                // =========================
                let proxy_file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    // .open(format!("logs/proxy_{}.log", date))
                    .open(format!("logs/proxy.log"))
                    .expect("Failed to open proxy log");

                let (proxy_writer, proxy_guard) = NonBlocking::new(proxy_file);
                guards.push(proxy_guard);

                let proxy_filter = Targets::new()
                    .with_default(tracing::Level::INFO)
                    .with_target("attack", tracing::Level::WARN);

                let proxy_layer = fmt::layer()
                    .with_writer(proxy_writer)
                    .json()
                    .with_filter(proxy_filter);

                // =========================
                // Лог атак WAF
                // =========================
                let attack_file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(format!("logs/attacks.log"))
                    .expect("Failed to open attack log");

                let (attack_writer, attack_guard) = NonBlocking::new(attack_file);
                guards.push(attack_guard);

                let attack_filter = Targets::new()
                    .with_target("attack", tracing::Level::WARN);

                let attack_layer = fmt::layer()
                    .with_writer(attack_writer)
                    .json()
                    .with_filter(attack_filter);

                // =========================
                // Консоль (если both)
                // =========================
                let registry = tracing_subscriber::registry()
                    .with(env_filter)
                    .with(proxy_layer)
                    .with(attack_layer);

                if cfg.output == "both" {
                    let console_layer = fmt::layer()
                        .with_ansi(cfg.enable_ansi);
                    registry.with(console_layer).init();
                } else {
                    registry.init();
                }
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

    info!("Tracing initialized");
    guards
}
