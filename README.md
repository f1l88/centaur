Centaur - Open Source Web Application Firewall on Rust
# Rust WAF Proxy (Pingora + ModSecurity SecRule + Hot Reload)

Production-ready пример WAF на Rust с использованием Pingora и поддержкой правил ModSecurity (`SecRule`).

## Возможности
- Поддержка `.conf` правил (`SecRule`)
- Actions: `id`, `phase`, `deny`, `msg`, `status`
- Hot reload правил:
  - по сигналу `SIGHUP`
  - по HTTP `POST /reload`
- Настройка через файл конфиг toml

## Запуск
```bash
cargo run
```

Reload:
```bash
curl -X POST http://127.0.0.1:8081/reload
# или
kill -HUP $(pgrep rust-waf-pingora-secrule-reload)
```

# Тест
```bash
1. cargo run
2. python3 -m http.server 8888 
3. curl -v -H "User-Agent: Mozilla/5.0 Chrome" http://127.0.0.1:6188/ - Allow
4. curl -v -H "User-Agent: BadBot" http://localhost:6188/ - Block
```