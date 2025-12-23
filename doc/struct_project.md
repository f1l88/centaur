centaur/                          # Project root directory
├── 📄 Cargo.toml                 # Rust dependencies configuration
├── 📄 Cargo.lock                 # Locked dependency versions
├── ⚙️ config.toml                # Application configuration
├── 📖 README.md                  # Project documentation
├── 📁 logs/                      # Logs directory
├── 📁 rules/                     # WAF rules (CRS - Core Rule Set)
│   ├── admin/                    # Rules for admin panel
│   ├── api/                      # Rules for API
│   ├── default/                  # Default rules
│   └── web/                      # Rules for web application
└── 📁 src/                       # Source code
    ├── 🚀 main.rs                # Entry point
    ├── 💻 cli/                   # CLI interface
    ├── ⚙️ config/                # Configuration handling
    ├── 📋 logger/                # Logging
    ├── 🔄 proxy/                 # Proxy functionality
    ├── 🛡️ waf/                   # WAF engine
    └── 🌐 web/                   # Web interface