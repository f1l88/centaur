use std::sync::Arc;
use std::collections::HashMap;

use pingora::Result;

use crate::config::config::Config;
use crate::proxy::proxy::MyProxy;

pub struct ProxyManager {
    pub proxies: HashMap<String, Arc<MyProxy>>,
    pub config: Config,
}

impl ProxyManager {
    pub fn new(config: Config) -> Self {
        let mut proxies = HashMap::new();
        
        for server_name in config.get_servers().keys() {
            let proxy = MyProxy::new_for_server(config.clone(), server_name);
            proxies.insert(server_name.clone(), Arc::new(proxy));
        }
        
        Self { proxies, config }
    }
    
    pub fn get_proxy(&self, server_name: &str) -> Option<Arc<MyProxy>> {
        self.proxies.get(server_name).cloned()
    }

    pub fn get_server_list(&self) -> Vec<String> {
        self.proxies.keys().cloned().collect()
    }
        
    pub fn reload_all_rules(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        
        for (name, proxy) in &self.proxies {
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
        for (server_name, proxy) in &self.proxies {
            info.push_str(&format!("=== Server: {} ===\n", server_name));
            info.push_str(&proxy.get_all_rules_info());
            info.push_str("\n");
        }
        info
    }

    // Добавим метод для получения информации о WAF (просто обертка для первого прокси)
    pub fn get_waf_info(&self) -> String {
        if let Some((first_name, first_proxy)) = self.proxies.iter().next() {
            format!("Proxy Manager - First server '{}': {}", first_name, first_proxy.get_waf_info())
        } else {
            "No proxies available".to_string()
        }
    }
        
    pub fn get_server_info(&self, server_name: &str) -> Option<String> {
        self.proxies.get(server_name)
        .map(|proxy| proxy.get_waf_info())
    }
}