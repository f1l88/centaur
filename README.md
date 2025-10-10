# 🏹 Centaur - Rust WAF Proxy (Open Source Web Application Firewall on Rust (Pingora + ModSecurity SecRule + Hot Reload))

![Rust](https://img.shields.io/badge/Rust-1.70+-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)
![Pingora](https://img.shields.io/badge/Powered_by-Pingora-green)

A high-performance Web Application Firewall (WAF) proxy built with **Rust** and **Pingora**, featuring ModSecurity rule support and hot-reload capabilities.

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🔒 Security** | ModSecurity-style rule support |
| **⚡ Performance** | Built on Pingora for high-throughput |
| **🔄 Hot Reload** | Rule updates without downtime |
| **📝 Rule Support** | Full SecRule syntax compatibility |
| **🔧 Configurable** | TOML-based configuration |
| **📊 Admin API** | HTTP API for management |

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+
- Cargo

### Project Structure
centaur/
├── src/
│   ├── main.rs          # Main application
│   ├── lib.rs           # Main application
│   └── waf/             # WAF engine
│       ├── mod.rs       # WAF module
│       ├── parser.rs    # Rule parser
│       └── reloader.rs  # Hot reload logic
├── rules/
│   └── example.conf     # WAF rules
├── config.toml          # Configuration
├── Cargo.toml
└── README.md

### Installation

```bash
# Clone the repository
git clone https://github.com/f1l88/centaur.git
cd centaur

# Build the project
cargo build --release

# Run the proxy
cargo run --release

## Quick Start
```bash
cargo run
```

Reload:
```bash
curl -X POST http://127.0.0.1:8081/reload
# or
kill -HUP $(pgrep rust-waf-pingora-secrule-reload)
```

## Testing
```bash
1. cargo run
2. python3 -m http.server 8888 
3. curl -v -H "User-Agent: Mozilla/5.0 Chrome" http://127.0.0.1:6188/ - Allow
4. curl -v -H "User-Agent: BadBot" http://localhost:6188/ - Block
```