use crate::waf::{Engine, WafCheckResult};
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::signal::unix::{signal, SignalKind};
use pingora::http::HMap;

use tracing::{debug, error, info, warn, instrument};

#[derive(Clone)]
pub struct SharedWaf {
    pub inner: Arc<RwLock<Engine>>,
    pub path: Arc<PathBuf>,
}

impl SharedWaf {
    #[instrument(name = "SharedWaf::new", skip_all)]
    pub fn new(engine: Engine, path: impl Into<PathBuf>) -> Self {
        let path_buf: PathBuf = path.into();
        info!("WAF инициализирован с файлом правил: {:?}", path_buf);

        Self {
            inner: Arc::new(RwLock::new(engine)),
            path: Arc::new(path_buf),
        }
    }

    // pub fn check(&self, headers: &HMap, uri: &str, _method: &str, _body: Option<&[u8]>) -> bool {
    //     let engine = self.inner.read().expect("WAF lock poisoned");
    //     engine.check(&headers, &uri, "GET", None)
    // }

    pub fn check_detailed(&self, headers: &HMap, uri: &str, _method: &str, _body: Option<&[u8]>) -> WafCheckResult {
        let engine = self.inner.read().expect("WAF lock poisoned");
        engine.check_detailed(&headers, &uri, &_method, _body)
    }

    // ... остальные методы остаются без изменений
    pub async fn watch_sighup(&self) {
        let mut stream = signal(SignalKind::hangup()).expect("failed to setup SIGHUP listener");
        info!("Начато отслеживание SIGHUP для перезагрузки правил WAF");

        while stream.recv().await.is_some() {
            info!("Получен SIGHUP, перезагружаем правила WAF");
            match Engine::load(&*self.path) {
                Ok(new_engine) => {
                    let rules_info = new_engine.get_rules_info();
                    *self.inner.write().unwrap() = new_engine;
                    info!("Правила WAF успешно перезагружены из {:?}", self.path);
                    debug!(rules_detailed = %rules_info, "Детальная информация о правилах");
                }
                Err(err) => {
                    error!(
                        error = %err,
                            "Не удалось получить блокировку для записи WAF engine"
                        );
                }
            }
        }
    }

    pub fn reload_now(&self) -> anyhow::Result<()> {
        info!("Принудительная перезагрузка правил WAF");
        let new_engine = Engine::load(&*self.path)?;
        let rules_info = new_engine.get_rules_info();
        *self.inner.write().unwrap() = new_engine;
        info!("Правила WAF успешно перезагружены");
        debug!("{}", rules_info);
        Ok(())
    }

    pub fn get_rules_info(&self) -> String {
        let engine = self.inner.read().expect("WAF lock poisoned");
        engine.get_rules_info()
    }
}
