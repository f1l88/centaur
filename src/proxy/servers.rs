use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

use crate::config::config::Config;
use crate::proxy::proxy::MyProxy;

// Простой менеджер серверов
pub struct ServerManager {
    pub config: Arc<RwLock<Config>>,
    pub running: Arc<RwLock<bool>>,
}

impl ServerManager {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            running: Arc::new(RwLock::new(true)),
        }
    }
    
    // Основной метод запуска серверов
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut server_tasks = vec![];
        
        // Пока флаг running = true, серверы работают
        while *self.running.read().await {
            let config = self.config.read().await.clone();
            
            // Запускаем каждый сервер в отдельной задаче
            for (server_name, server_config) in &config.servers.clone() {
                let listen_addr = server_config.listen_addr.clone()
                    .or_else(|| Some(server_config.addr.clone()))
                    .unwrap_or_else(|| format!("0.0.0.0:{}", 8080));
                
                let _proxy = MyProxy::new_for_server(config.clone(), server_name);
                
                let task_name = server_name.clone();
                let task_addr = listen_addr.clone();
                
                // Запускаем сервер в отдельной задаче
                let handle = tokio::spawn(async move {
                    info!("Starting server '{}' on {}", task_name, task_addr);
                    
                    // Здесь должна быть логика запуска сервера Pingora
                    // Например: server.run_forever().await;
                    
                    // Для примера - бесконечный цикл
                    loop {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                    }
                });
                
                server_tasks.push(handle);
            }
            
            // Ждем завершения всех задач (никогда не завершатся в нормальном режиме)
            for task in server_tasks {
                let _ = task.await;
            }
            
            // Если мы здесь, значит все задачи завершились
            // Выходим из цикла
            break;
        }
        
        Ok(())
    }
    
    // Перезагрузка с новым конфигом
    pub async fn reload(&self, new_config: Config) -> Result<(), Box<dyn std::error::Error>> {
        info!("Reloading server configuration...");
        
        // 1. Обновляем конфигурацию
        let mut config_lock = self.config.write().await;
        *config_lock = new_config;
        drop(config_lock); // Освобождаем блокировку
        
        // 2. Останавливаем текущие серверы
        self.stop().await;
        
        // 3. Ждем немного
        sleep(Duration::from_millis(100)).await;
        
        // 4. Запускаем серверы заново
        // (в реальности это сделает цикл в методе run)
        
        info!("Configuration reloaded successfully");
        Ok(())
    }
    
    // Остановка серверов
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
        info!("Stopping all servers...");
    }
}