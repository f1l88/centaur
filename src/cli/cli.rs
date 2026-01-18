use clap::{Parser, Subcommand};
use crate::config::config::Config;
use crate::proxy::proxy::run_server;
use crate::proxy::manager::ProxyManager;
use crate::web::api::run_admin_server;
use tracing::{info, warn};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "centaur")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "WAF Proxy Server", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run WAF proxy server
    Run {
        /// Start in upgrade mode (wait for upgrade socket)
        #[arg(long)]
        upgrade: bool,
    },
    RunAdmin { #[arg(long)] port: u16 },
    /// Check WAF rules
    Check {
        rules: String,
    },
    /// Reload WAF rules
    Reload,
    /// Show statistics
    Stats,
    /// Show loaded rules info
    Info,
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    pub fn execute(&self, mut config: Config) -> Result<(), Box<dyn std::error::Error>> {
        match &self.command {
            Some(Commands::Run { upgrade }) => {
            // Создаем mutable config
            if *upgrade {
                // CLI-флаг --upgrade имеет приоритет
                config.enable_upgrade();
            }

            // Передаем config в run_server
            run_server(config)?;
            Ok(())
            }

            Some(Commands::RunAdmin { port }) => {
                let config = Config::load();
                let pm = ProxyManager::new(config);
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async { run_admin_server(*port, Arc::new(pm)).await });
                Ok(())
            }

            Some(Commands::Check { rules }) => {
                use crate::waf::engine::Engine;

                match Engine::load(rules) {
                    Ok(_) => {
                        info!("✓ Rules loaded successfully: {}", rules);
                        Ok(())
                    }
                    Err(e) => {
                        warn!("✗ Error loading rules: {}", e);
                        Err(e.into())
                    }
                }
            }

            Some(Commands::Reload) => {
                info!("Sending reload request to admin API...");
                Ok(())
            }

            Some(Commands::Stats) => {
                info!("Fetching statistics from admin API...");
                Ok(())
            }

            Some(Commands::Info) => {
                info!("WAF Proxy Information:");
                info!("  Version: {}", env!("CARGO_PKG_VERSION"));
                info!("  Configuration loaded from: config.toml");
                Ok(())
            }

            // Если subcommand не указан, запускаем Pingora напрямую
            None => {
                // Запускаем Pingora + прокси
                run_server(config)?;
                Ok(())
            }
        }
    }
}
