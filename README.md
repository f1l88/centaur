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
- Rust 1.90+
- cargo 1.90.0

### Installation ModSecurity
```bash
# Install on Debian 13

sudo apt install gcc make build-essential autoconf automake libtool libcurl4-openssl-dev liblua5.3-dev libfuzzy-dev ssdeep gettext pkg-config libpcre3 libpcre3-dev libxml2 libxml2-dev libcurl4 libgeoip-dev libyajl-dev doxygen libpcre2-16-0 libpcre2-dev libpcre2-posix3 -y

git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity /usr/local/src/ModSecurity/
cd /usr/local/src/ModSecurity/

git submodule init
git submodule update

./build.sh
./configure

make
make install

export PKG_CONFIG_PATH=/usr/local/modsecurity/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/modsecurity/lib:$LD_LIBRARY_PATH

```

### Installation Centaur WAF
```bash
# Clone the repository
git clone https://github.com/f1l88/centaur.git
cd centaur

# Build the project
cargo build --release

# Run the proxy
cargo run -- run
RUST_LOG=trace cargo run -- run
```
## Install CoreRuleset
```bash
git clone https://github.com/coreruleset/coreruleset
```

Reload:
```bash
curl -X POST http://127.0.0.1:8081/reload /servers
# or
kill -HUP $(pgrep rust-waf-pingora-secrule-reload)
```

## API
```bash
# Get List Servers
curl http://127.0.0.1:8081/server/

# Get information about a specific server
curl http://127.0.0.1:8081/server/Server1
curl http://127.0.0.1:8081/server/Server2

# Other endpoints
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/stats
curl http://127.0.0.1:8081/info
curl -X POST http://127.0.0.1:8081/reload

```

## Testing
```bash
1. cargo run
2. python3 -m http.server 8888
3. curl -v -H "User-Agent: Mozilla/5.0 Chrome" http://127.0.0.1:6188/ - Allow
4. curl -v -H "User-Agent: BadBot" http://localhost:6188/ - Block
5. curl -v -H "User-Agent: Mozilla/5.0 Chrome" http://127.0.0.1:6188/admin - Block
6. curl -v -H "X-Client-Port: 22" -H "User-Agent: Test" http://127.0.0.1:6188/ - Block
7. curl -v -H "User-Agent: BadBot" -H "Host: admin.example.com" http://localhost:6188/
8. curl -v -H "Host: admin.example.com" -A "masscan" "http://127.0.0.1:6188/"
9. curl -v -X POST "http://localhost:6188"   -H "Host: admin.example.com"   -H "Content-Type: application/json"   -d '{"input": "<script>alert(\"xss\")</script>"}'
```

## Perform testing
```bash
sudo apt install wrk  # Ubuntu/Debian

# Базовый тест
wrk -t12 -c100 -d30s -H "Host: admin.example.com" -H "User-Agent: masscan" "http://127.0.0.1:6188/"
```

## Logging 
```bash
RUST_LOG=debug ./your_proxy
# или
RUST_LOG=pingwaf=info,hyper=warn ./your_proxy

```

```toml
admin_port = 8081

[servers.Server1]
addr = "0.0.0.0:6188"
upstreams = ["Upstream1"]

[servers.Server2]
addr = "0.0.0.0:6189"
upstreams = ["Upstream2"]

[upstreams.web]
addrs = ["127.0.0.1:8080"]
use_tls = false
sni = "www.example.com"
waf_rules = "web"

[upstreams.admin]
addrs = ["127.0.0.2:8888"]
use_tls = false  
sni = "admin.example.com"
waf_rules = "admin"
```