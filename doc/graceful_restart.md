```bash
ss -lntp | grep 6188
ss -lntp | grep 6189
ss -lntp | grep 8082

pidof -x centaur # поиск pid по имени процесса

kill -QUIT <PID старого процесса> # graceful shutdown старого процесса
kill <PID старого процесса> # принудительно убить старый процесс

cargo run -- run # обычный запуск
cargo run -- run --upgrade # запуск с обновлением

# старый процесс
cargo run -- run &

# новый
cargo run -- run --upgrade &

# переключение
kill -QUIT $(pidof centaur)


kill $(pidof centaur)

# тест graceful restart

watch -n 0.2 'curl -s -o /dev/null -w "%{http_code}\n" -H "Host: admin.example.com" http://localhost:6191'

```

