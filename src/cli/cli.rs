use clap::{Parser, Subcommand};
use crate::config::config::Config;

#[derive(Parser)]
#[command(name = "pingwaf")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "WAF Proxy Server", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run WAF proxy server
    Run,
    /// Check WAF rules
    Check {
        /// Path to rules file
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
    
    pub fn execute(&self, config: Config) -> Result<(), Box<dyn std::error::Error>> {
        match &self.command {
            Commands::Run => {
                crate::proxy::proxy::run_server(config)
            }
            Commands::Check { rules } => {
                use crate::waf::engine::Engine;
                
                match Engine::load(rules) {
                    Ok(_) => {
                        println!("✓ Rules loaded successfully: {}", rules);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("✗ Error loading rules: {}", e);
                        Err(e.into())
                    }
                }
            }
            Commands::Reload => {
                println!("Sending reload request to admin API...");
                Ok(())
            }
            Commands::Stats => {
                println!("Fetching statistics from admin API...");
                Ok(())
            }
            Commands::Info => {
                println!("WAF Proxy Information:");
                println!("  Version: {}", env!("CARGO_PKG_VERSION"));
                println!("  Configuration loaded from: config.toml");
                Ok(())
            }
        }
    }
}