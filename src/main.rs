mod cli;
mod config;
mod logger;
mod proxy;
mod waf;
mod web;

use cli::cli::Cli;
use config::config::Config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments
    let cli = Cli::parse();
    
    // Load config
    let config = Config::load();
    
    // Initialize logger
    logger::logger::init_tracing(&config.tracing);
    
    // Execute command
    cli.execute(config)?;
    
    Ok(())
}