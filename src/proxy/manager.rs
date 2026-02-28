use std::sync::Arc;
use std::sync::RwLock;
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;
use std::thread::sleep;

use pingora::Result;

use crate::config;
use crate::config::config::Config;
use crate::proxy::proxy::MyProxy;

use std::process::{Command, Stdio};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use tracing::info;

pub struct ProxyManager {
    proxies: Arc<RwLock<HashMap<String, Arc<MyProxy>>>>,
    config: Arc<RwLock<Config>>,
}

/// Проверяет, жив ли процесс
fn is_process_alive(pid: Pid) -> bool {
    kill(pid, None).is_ok()
}

impl ProxyManager {
    pub fn new(config: Config) -> Self {
        let mut proxies = HashMap::new();
        
        for server_name in config.get_servers().keys() {
            let proxy = MyProxy::new_for_server(config.clone(), server_name);
            proxies.insert(server_name.clone(), Arc::new(proxy));
        }
        
        Self {
            proxies: Arc::new(RwLock::new(proxies)),
            config: Arc::new(RwLock::new(config)),
        }
    }

    pub async fn upgrade_master(&self) -> Result<(), String> {
        tracing::info!("Starting hot upgrade");

        let pid = crate::utils::pid::read_pid("/tmp/centaur.pid")
            .map_err(|e| format!("failed to read pid: {e}"))?;

        let pid_i32 = i32::try_from(pid)
            .map_err(|e| format!("pid out of range: {e}"))?;

        tracing::info!(
            "About to SIGQUIT pid={}, self pid={}",
            pid_i32,
            std::process::id()
        );

        // 🔥 1. Spawn НОВОГО процесса ВНЕ async executor
        tokio::task::spawn_blocking(|| {
            Command::new(std::env::current_exe()
                .map_err(|e| e.to_string())?)
                .arg("run")
                .arg("--upgrade")
                .arg("--conf")
                .arg("./config.toml")
                .spawn() 
                .map_err(|e| format!("Failed to spawn upgrade process: {e}"))?;
            Ok::<_, String>(())
        })
        .await
        .map_err(|e| format!("Join error: {e}"))??;

        // ✅ 2. Неблокирующая пауза
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        tracing::info!("Sending SIGQUIT to old process");

        // 🔥 3. SIGQUIT тоже лучше вынести
        tokio::task::spawn_blocking(move || {
            kill(Pid::from_raw(pid_i32), Signal::SIGQUIT)
                .map_err(|e| format!("failed to send SIGQUIT to {pid_i32}: {e}"))
        })
        .await
        .map_err(|e| format!("Join error: {e}"))??;

        Ok(())
    }

    pub fn apply_enabled_servers(
        &self,
        server: &mut pingora::server::Server,
    ) {
        for (name, cfg) in self.config.read().unwrap().get_servers() {
            if !cfg.enabled {
                tracing::info!("Not adding disabled server {}", name);
                continue;
            }

            let proxy = self.get_proxy(&name).unwrap();
            let mut svc = pingora::proxy::http_proxy_service(
                &server.configuration,
                proxy.as_ref().clone(),
            );

            svc.add_tcp(&cfg.addr);
            server.add_service(svc);
        }
    }

    pub async fn upgrade_master_async(&self) -> Result<(), String> {
        info!("Starting async hot upgrade");

        // 1️⃣ Читаем pid старого процесса
        let pid = crate::utils::pid::read_pid("/tmp/centaur.pid")
            .map_err(|e| format!("failed to read pid: {e}"))?;
        let pid_i32 = i32::try_from(pid).map_err(|e| format!("pid out of range: {e}"))?;
        let old_pid = Pid::from_raw(pid_i32);

        // 2️⃣ Запускаем новый процесс с --upgrade
        Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("run")
            .arg("--upgrade")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to spawn upgrade process: {e}"))?;

        // 3️⃣ Ждём немного, чтобы новый процесс забрал сокеты
        sleep(Duration::from_millis(300));

        // 4️⃣ SIGQUIT старому процессу (graceful shutdown)
        info!("Sending SIGQUIT to pid={}", pid_i32);
        kill(old_pid, Signal::SIGQUIT)
            .map_err(|e| format!("failed to send SIGQUIT: {e}"))?;

        // 5️⃣ Ждём graceful shutdown с polling
        let grace = Duration::from_secs(60);
        let start = Instant::now();
        while start.elapsed() < grace {
            if !is_process_alive(old_pid) {
                info!("Old process exited gracefully");
                return Ok(());
            }
            sleep(Duration::from_millis(500));
        }

        // 6️⃣ Если не умер — убиваем насильно
        info!("Old process did not exit in time, sending SIGKILL");
        kill(old_pid, Signal::SIGKILL)
            .map_err(|e| format!("failed to send SIGKILL: {e}"))?;

        Ok(())
    }

    // ОДНА ПРОСТАЯ РУЧКА ДЛЯ ПЕРЕЗАГРУЗКИ
    pub fn reload(&self) -> Result<(), String> {
        let new_config = Config::load();

        // ❗ Обновляем config
        {
            *self.config.write().unwrap() = new_config.clone();
        }

        tracing::info!("Reload applied");
        Ok(())
    }

    pub fn get_proxy(&self, server_name: &str) -> Option<Arc<MyProxy>> {
        self.proxies.read().unwrap().get(server_name).cloned()
    }

    pub fn get_server_list(&self) -> Vec<String> {
        self.proxies.read().unwrap().keys().cloned().collect()
    }
        
    pub fn reload_all_rules(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        
        for (name, proxy) in self.proxies.read().unwrap().iter() {
            if let Err(e) = proxy.reload_all_rules() {
                errors.push(format!("Failed to reload rules for {}: {}", name, e));
            }
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn get_all_rules_info(&self) -> String {
        let mut info = String::new();
        for (server_name, proxy) in self.proxies.read().unwrap().iter() {
            info.push_str(&format!("=== Server: {} ===\n", server_name));
            info.push_str(&proxy.get_all_rules_info());
            info.push_str("\n");
        }
        info
    }

    // Добавим метод для получения информации о WAF (просто обертка для первого прокси)
    pub fn get_waf_info(&self) -> String {
        if let Some((first_name, first_proxy)) = self.proxies.read().unwrap().iter().next() {
            format!("Proxy Manager - First server '{}': {}", first_name, first_proxy.get_waf_info())
        } else {
            "No proxies available".to_string()
        }
    }
        
    pub fn get_server_info(&self, server_name: &str) -> Option<String> {
        self.proxies.read().unwrap().get(server_name)
            .map(|proxy| proxy.get_waf_info())
    }

    pub fn get_server_config_info(&self) -> String {
        let config = self.config.read().unwrap();

        if config.servers.is_empty() {
            return "No servers configured".to_string();
        }

        // Создаём вектор строк для каждого сервера
        let mut output = vec![];
        for (name, server) in &config.servers {
            // Используем Debug для вывода всех полей
            output.push(format!("Server '{}': {:?}", name, server));
        }

        // Объединяем все строки через перенос строки
        output.join("\n")
    }
    
}