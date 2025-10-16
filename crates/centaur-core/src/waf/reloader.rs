use std::{sync::{Arc, RwLock}, path::PathBuf};
use tokio::signal::unix::{signal, SignalKind};
use crate::waf::Engine;

#[derive(Clone)]
pub struct SharedWaf {
    pub inner: Arc<RwLock<Engine>>,
    pub path: Arc<PathBuf>,
}

impl SharedWaf {
    pub fn new(engine: Engine, path: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(engine)),
            path: Arc::new(path.into()),
        }
    }

    pub async fn watch_sighup(self) {
        let mut stream = signal(SignalKind::hangup()).expect("failed to setup SIGHUP listener");
        while stream.recv().await.is_some() {
            match Engine::load(&*self.path) {
                Ok(new_engine) => {
                    *self.inner.write().unwrap() = new_engine;
                    println!("🔄 Rules reloaded successfully from {:?}", self.path);
                }
                Err(err) => eprintln!("⚠️ Failed to reload rules: {err:?}"),
            }
        }
    }

    pub fn reload_now(&self) -> anyhow::Result<()> {
        let new_engine = Engine::load(&*self.path)?;
        *self.inner.write().unwrap() = new_engine;
        Ok(())
    }
}
