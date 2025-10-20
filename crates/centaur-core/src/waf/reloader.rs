use crate::waf::{Engine, WafCheckResult};
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::signal::unix::{signal, SignalKind};

#[derive(Clone)]
pub struct SharedWaf {
    pub inner: Arc<RwLock<Engine>>,
    pub path: Arc<PathBuf>,
}

impl SharedWaf {
    pub fn new(engine: Engine, path: impl Into<PathBuf>) -> Self {
        let path_buf: PathBuf = path.into();
        println!("🛡️  WAF инициализирован с файлом правил: {:?}", path_buf);

        Self {
            inner: Arc::new(RwLock::new(engine)),
            path: Arc::new(path_buf),
        }
    }

    pub fn check(&self, headers: &pingora::http::HMap, uri: &str) -> bool {
        let engine = self.inner.read().expect("WAF lock poisoned");
        engine.check(headers, uri)
    }

    pub fn check_detailed(&self, headers: &pingora::http::HMap, uri: &str) -> WafCheckResult {
        let engine = self.inner.read().expect("WAF lock poisoned");
        engine.check_detailed(headers, uri)
    }

    // ... остальные методы остаются без изменений
    pub async fn watch_sighup(self) {
        let mut stream = signal(SignalKind::hangup()).expect("failed to setup SIGHUP listener");
        println!("🔭 Начато отслеживание SIGHUP для перезагрузки правил WAF");

        while stream.recv().await.is_some() {
            println!("🔄 Получен SIGHUP, перезагружаем правила WAF...");
            match Engine::load(&*self.path) {
                Ok(new_engine) => {
                    let rules_info = new_engine.get_rules_info();
                    *self.inner.write().unwrap() = new_engine;
                    println!("✅ Правила WAF успешно перезагружены из {:?}", self.path);
                    println!("   {}", rules_info);
                }
                Err(err) => eprintln!("⚠️ Не удалось перезагрузить правила: {err:?}"),
            }
        }
    }

    pub fn reload_now(&self) -> anyhow::Result<()> {
        println!("🔄 Принудительная перезагрузка правил WAF...");
        let new_engine = Engine::load(&*self.path)?;
        let rules_info = new_engine.get_rules_info();
        *self.inner.write().unwrap() = new_engine;
        println!("✅ Правила WAF успешно перезагружены");
        println!("   {}", rules_info);
        Ok(())
    }

    pub fn get_rules_info(&self) -> String {
        let engine = self.inner.read().expect("WAF lock poisoned");
        engine.get_rules_info()
    }
}
