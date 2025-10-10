# Centaur - Open Source Web Application Firewall on Rust (Pingora + ModSecurity SecRule + Hot Reload)
Production-ready WAF example on Rust using Pingora with ModSecurity rules (SecRule) support.

## Features
- Поддержка `.conf` правил (`SecRule`)
- Actions: `id`, `phase`, `deny`, `msg`, `status`
- Hot reload правил:
  - по сигналу `SIGHUP`
  - по HTTP `POST /reload`
- Настройка через файл конфиг toml

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