use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

// Импорты из pingora для проксирования HTTP запросов
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::http::HMap;
use pingora::Result;
use pingora::server::configuration::Opt;

use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// Импорты из вашего проекта
use crate::waf::reloader::SharedWaf;
use crate::waf::Engine;
use crate::config::config::{Config, UpstreamConfig, RateLimitConfig};
use crate::proxy::inspector::BodyInspector;
use crate::proxy::manager::ProxyManager;

use bytes::Bytes;
use chrono::Utc;

use tracing::{debug, error, info, warn, instrument};

// ==================== ВСПОМОГАТЕЛЬНЫЕ СТРУКТУРЫ ====================

/// Структура для хранения информации о нарушении WAF
#[derive(Clone, Debug)]
pub struct WafViolation {
    pub rule_id: u32,           // ID правила, которое сработало
    pub reason: String,         // Причина блокировки
    pub blocked: bool,          // Было ли блокировано (true) или только залогировано
    pub timestamp: chrono::DateTime<Utc>, // Время нарушения
    pub source: String,         // Источник: "header" или "body"
}

/// Структура для реализации rate limiting
#[derive(Debug, Clone)]
struct RateLimiter {
    // Хранилище запросов: ключ (IP/upstream) -> список временных меток запросов
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    window_duration: Duration,  // Длительность временного окна
    max_requests: usize,        // Максимальное количество запросов за окно
    enabled: bool,              // Включен ли rate limiter
}

impl RateLimiter {
    /// Создает RateLimiter из конфигурации
    fn from_config(config: &RateLimitConfig) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            window_duration: Duration::from_secs(config.window_seconds),
            max_requests: config.max_requests,
            enabled: config.enabled,
        }
    }

    /// Создает отключенный RateLimiter (используется как заглушка)
    fn disabled() -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            window_duration: Duration::from_secs(60),
            max_requests: 100,
            enabled: false,
        }
    }

    /// Проверяет, не превышен ли лимит для ключа, и записывает запрос
    /// Возвращает Ok(true) если запрос разрешен, Err с сообщением если лимит превышен
    async fn check_and_record(&self, key: &str) -> Result<bool, String> {
        if !self.enabled {
            return Ok(true); // Если отключен, всегда разрешаем
        }

        let mut map = self.requests.lock().await;
        let now = Instant::now();
        
        // Получаем или создаем список временных меток для ключа
        let timestamps = map.entry(key.to_string()).or_insert_with(Vec::new);
        
        // Удаляем старые записи вне временного окна
        timestamps.retain(|&t| now.duration_since(t) < self.window_duration);
        
        // Проверяем лимит
        if timestamps.len() >= self.max_requests {
            return Err(format!("Rate limit exceeded for {}", key));
        }
        
        // Добавляем текущий запрос
        timestamps.push(now);
        Ok(true)
    }

    /// Возвращает количество оставшихся доступных запросов для ключа
    async fn get_remaining(&self, key: &str) -> usize {
        if !self.enabled {
            return self.max_requests;
        }

        let map = self.requests.lock().await;
        let now = Instant::now();
        
        if let Some(timestamps) = map.get(key) {
            // Считаем валидные запросы в текущем окне
            let valid = timestamps.iter()
                .filter(|&&t| now.duration_since(t) < self.window_duration)
                .count();
            self.max_requests.saturating_sub(valid)
        } else {
            self.max_requests
        }
    }

    fn get_limit(&self) -> usize {
        self.max_requests
    }
}

/// Контекст запроса - хранит состояние обработки текущего запроса
pub struct RequestContext {
    pub body_inspector: BodyInspector,    // Для инспекции тела запроса
    pub upstream_name: Option<String>,     // Имя выбранного upstream
    pub client_ip: String,                // IP клиента
    pub violations: Vec<WafViolation>,    // Список нарушений
    pub rate_limit_remaining: Option<usize>, // Оставшиеся запросы по rate limit
    pub rate_limit_limit: Option<usize>,      // Максимальный лимит
}

impl RequestContext {
    pub fn new(client_ip: &str) -> Self {
        Self {
            body_inspector: BodyInspector::new(10 * 1024 * 1024, true), // 10 MB лимит тела
            upstream_name: None,
            client_ip: client_ip.to_string(),
            violations: Vec::new(),
            rate_limit_remaining: None,
            rate_limit_limit: None,
        }
    }
}

// ==================== ОСНОВНОЙ ПРОКСИ-КЛАСС ====================

/// Основная структура прокси с WAF функциональностью
pub(crate) struct MyProxy {
    // Хранилище WAF движков для каждого upstream
    waf_engines: HashMap<String, Arc<SharedWaf>>,
    config: Config,                         // Конфигурация приложения
    server_name: String,                    // Имя текущего сервера
    rate_limiter: Arc<RateLimiter>,         // Rate limiter на уровне сервера
    upstream_rate_limiters: HashMap<String, Arc<RateLimiter>>, // Rate limiters для upstream
}

impl MyProxy {
    /// Создает новый экземпляр прокси для указанного сервера
    /// Загружает WAF правила и настраивает rate limiters для каждого upstream
    #[instrument(name = "MyProxy::new_for_server")]
    pub fn new_for_server(config: Config, server_name: &str) -> Self {
        let server = config.get_server(server_name)
            .unwrap_or_else(|| panic!("Server '{}' not found in config", server_name));

        let mut waf_engines = HashMap::new();
        let mut upstream_rate_limiters = HashMap::new();

        info!("Loading WAF rules for each upstream");

        // Загружаем WAF правила для каждого upstream
        for upstream_key in &server.upstreams {
            let upstream = config.get_upstream(upstream_key)
                .unwrap_or_else(|| panic!("Upstream '{}' not found in config", upstream_key));
            
            // Формируем путь к правилам WAF
            let rules_path = format!(
                "{}/rules/{}/crs-setup.conf", 
                env!("CARGO_MANIFEST_DIR"),
                upstream.waf_rules
            );
            
            // Пытаемся загрузить движок WAF
            match Engine::load(&rules_path) {
                Ok(engine) => {
                    let shared_waf = Arc::new(SharedWaf::new(engine, rules_path.clone()));
                    waf_engines.insert(upstream_key.clone(), shared_waf);
                    debug!(upstream = %upstream_key, rules = %upstream.waf_rules, "WAF rules loaded successfully");
                }
                Err(e) => {
                    error!(upstream = %upstream_key, rules = %upstream.waf_rules, error = %e, "Failed to load WAF rules");
                    
                    // Fallback: пробуем загрузить дефолтные правила
                    let default_path = format!("{}/rules/default/default.conf", env!("CARGO_MANIFEST_DIR"));
                    match Engine::load(&default_path) {
                        Ok(engine) => {
                            let shared_waf = Arc::new(SharedWaf::new(engine, default_path));
                            waf_engines.insert(upstream_key.clone(), shared_waf);
                            warn!(upstream = %upstream_key, "Using default rules");
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to load default rules");
                            // Последний fallback: пустой движок
                            match Engine::load("") {
                                Ok(engine) => {
                                    let shared_waf = Arc::new(SharedWaf::new(engine, "empty".to_string()));
                                    waf_engines.insert(upstream_key.clone(), shared_waf);
                                    warn!(upstream = %upstream_key, "Using empty rules as fallback");
                                }
                                Err(e) => {
                                    error!(error = %e, "Failed to create empty engine");
                                    panic!("Cannot continue without WAF engine");
                                }
                            }
                        }
                    }
                }
            }

            // Настраиваем rate limiter для upstream
            let rate_limiter = if let Some(rl_config) = &upstream.rate_limit {
                info!(upstream = %upstream_key, "Rate limiting enabled for upstream: {} req/{}s", 
                    rl_config.max_requests, rl_config.window_seconds);
                Arc::new(RateLimiter::from_config(rl_config))
            } else {
                Arc::new(RateLimiter::disabled())
            };
            upstream_rate_limiters.insert(upstream_key.clone(), rate_limiter);
        }

        // Настраиваем rate limiter для сервера
        let server_rate_limiter = if let Some(rl_config) = &server.rate_limit {
            info!(server = %server_name, "Rate limiting enabled for server: {} req/{}s", 
                rl_config.max_requests, rl_config.window_seconds);
            Arc::new(RateLimiter::from_config(rl_config))
        } else {
            Arc::new(RateLimiter::disabled())
        };

        Self { 
            waf_engines, 
            config,
            server_name: server_name.to_string(),
            rate_limiter: server_rate_limiter,
            upstream_rate_limiters,
        }
    }

    /// Определяет upstream на основе Host заголовка
    /// Возвращает (ключ upstream, конфигурация upstream) если найден
    fn get_upstream_key_and_config_for_host(&self, host: &str) -> Option<(&String, &UpstreamConfig)> {
        let server = self.config.get_server(&self.server_name)?;
        
        for upstream_key in &server.upstreams {
            if let Some(upstream) = self.config.get_upstream(upstream_key) {
                // Проверяем точное совпадение или вхождение SNI в host
                if host.to_lowercase() == upstream.sni.to_lowercase() {
                    return Some((upstream_key, upstream));
                }
                if host.contains(&upstream.sni.to_lowercase()) {
                    return Some((upstream_key, upstream));
                }
            }
        }
        
        None
    }

    /// Проверяет rate limit для конкретного upstream
    /// Возвращает Ok(true) если лимит превышен (нужно блокировать)
    async fn check_rate_limit(&self, ctx: &mut RequestContext) -> pingora::Result<bool> {
        let upstream_name = match &ctx.upstream_name {
            Some(name) => name,
            None => return Ok(false),
        };

        let upstream_limiter = match self.upstream_rate_limiters.get(upstream_name) {
            Some(limiter) => limiter,
            None => return Ok(false),
        };

        if !upstream_limiter.enabled {
            debug!(upstream = %upstream_name, "Rate limit disabled for upstream");
            return Ok(false);
        }

        // Ключ для rate limiting: upstream + IP клиента (без порта)
        let client_ip_only = ctx.client_ip
            .split(':')
            .next()
            .unwrap_or(&ctx.client_ip)
            .to_string();

        let rate_limit_key = format!("{}:{}", upstream_name, client_ip_only);
        
        debug!(
            "Checking rate limit for key: {}, enabled: {}, max_requests: {}, window: {:?}", 
            rate_limit_key, 
            upstream_limiter.enabled,
            upstream_limiter.max_requests,
            upstream_limiter.window_duration
        );

        match upstream_limiter.check_and_record(&rate_limit_key).await {
            Ok(_) => {
                let remaining = upstream_limiter.get_remaining(&rate_limit_key).await;
                ctx.rate_limit_remaining = Some(remaining);
                ctx.rate_limit_limit = Some(upstream_limiter.get_limit());
                
                debug!(
                    "Rate limit passed for {}: {}/{} remaining", 
                    rate_limit_key, remaining, upstream_limiter.max_requests
                );
                
                Ok(false) // Не блокируем
            }
            Err(e) => {
                warn!(
                    target: "rate_limit",
                    client_ip = %client_ip_only,
                    upstream = %upstream_name,
                    "Upstream rate limit exceeded: {}",
                    e
                );
                
                // Добавляем нарушение в контекст
                ctx.violations.push(WafViolation {
                    rule_id: 429,
                    reason: format!("Rate limit exceeded for upstream {}", upstream_name),
                    blocked: true,
                    timestamp: Utc::now(),
                    source: "rate_limit_upstream".to_string(),
                });
                
                Ok(true) // Блокируем запрос
            }
        }
    }

    /// Проверяет server-level rate limit (по IP)
    async fn check_server_rate_limit(&self, ctx: &mut RequestContext) -> pingora::Result<bool> {
        if !self.rate_limiter.enabled {
            return Ok(false);
        }

        let rate_limit_key = ctx.client_ip.clone();

        match self.rate_limiter.check_and_record(&rate_limit_key).await {
            Ok(_) => {
                let remaining = self.rate_limiter.get_remaining(&rate_limit_key).await;
                // Не перезаписываем upstream лимит, если он уже есть
                if ctx.rate_limit_remaining.is_none() {
                    ctx.rate_limit_remaining = Some(remaining);
                    ctx.rate_limit_limit = Some(self.rate_limiter.get_limit());
                }
                
                debug!(
                    client_ip = %ctx.client_ip,
                    remaining = %remaining,
                    limit = %self.rate_limiter.get_limit(),
                    "Server rate limit check passed"
                );
                
                Ok(false)
            }
            Err(e) => {
                warn!(
                    target: "rate_limit",
                    client_ip = %ctx.client_ip,
                    "Server rate limit exceeded: {}",
                    e
                );
                
                ctx.violations.push(WafViolation {
                    rule_id: 429,
                    reason: "Server rate limit exceeded".to_string(),
                    blocked: true,
                    timestamp: Utc::now(),
                    source: "rate_limit_server".to_string(),
                });
                
                Ok(true)
            }
        }
    }

    /// Возвращает информацию о загруженных WAF движках
    pub fn get_waf_info(&self) -> String {
        let mut info = String::from(format!("WAF Engines for server '{}': ", self.server_name));
        let mut first = true;
        
        for (upstream_name, waf) in &self.waf_engines {
            let rules_info = waf.get_rules_info();
            let main_info = rules_info.lines().next().unwrap_or("").trim();
            
            if !first {
                info.push_str(", ");
            }
            info.push_str(&format!("{}: {}", upstream_name, main_info));
            first = false;
            
            debug!(
                upstream = %upstream_name,
                path = %waf.path.display(),
                "WAF engine"
            );
        }
        
        info
    }

    /// Запускает отслеживание SIGHUP сигнала для перезагрузки правил
    pub async fn watch_all_sighup(&self) {
        let mut handles = vec![];
        for (name, waf) in &self.waf_engines {
            let waf_clone = waf.clone();
            let name_clone = name.clone();
            let handle = tokio::spawn(async move {
                info!("Watching SIGHUP for {}", name_clone);
                waf_clone.watch_sighup().await;
            });
            handles.push(handle);
        }
        
        for handle in handles {
            let _ = handle.await;
        }
    }

    /// Перезагружает все WAF правила немедленно
    pub fn reload_all_rules(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        
        for (name, waf) in &self.waf_engines {
            match waf.reload_now() {
                Ok(_) => info!("Successfully reloaded rules for {}", name),
                Err(e) => {
                    let error_msg = format!("Failed to reload rules for {}: {}", name, e);
                    errors.push(error_msg.clone());
                    println!("❌ {}", error_msg);
                }
            }
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Получает информацию о всех правилах
    pub fn get_all_rules_info(&self) -> String {
        let mut info = String::new();
        for (name, waf) in &self.waf_engines {
            info.push_str(&format!("=== {} ===\n{}\n", name, waf.get_rules_info()));
        }
        info
    }
}

// Реализация Clone для MyProxy (необходима для работы с Pingora)
impl Clone for MyProxy {
    fn clone(&self) -> Self {
        let mut waf_engines = HashMap::new();
        for (name, waf) in &self.waf_engines {
            waf_engines.insert(name.clone(), waf.clone());
        }
        
        Self {
            waf_engines,
            config: self.config.clone(),
            server_name: self.server_name.clone(),
            rate_limiter: self.rate_limiter.clone(),
            upstream_rate_limiters: self.upstream_rate_limiters.clone(),
        }
    }
}

/// Преобразует конфигурацию в настройки Pingora
fn build_pingora_opt_from_config(config: &Config) -> Opt {
    Opt {
        upgrade: config.upgrade_mode,
        daemon: false,
        nocapture: false,
        test: false,
        conf: None,
    }
}

// ==================== РЕАЛИЗАЦИЯ TRAIT PROXYHTTP ====================

#[async_trait::async_trait]
impl ProxyHttp for MyProxy {
    type CTX = Option<RequestContext>; // Тип контекста - опциональный

    /// Создает новый контекст для каждого запроса
    fn new_ctx(&self) -> Self::CTX {
        None // Инициализируем как None, будет создан в request_filter
    }

    /// Выбирает апстрим для запроса
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        // Извлекаем Host заголовок
        let host_header = session
            .req_header()
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        // Определяем upstream по host
        let (upstream_key, upstream) = self.get_upstream_key_and_config_for_host(&host_header)
            .expect("No upstream configured for this host");

        // Сохраняем имя upstream в контексте
        if let Some(ctx) = ctx {
            ctx.upstream_name = Some(upstream_key.clone());
        }

        debug!(
            server = %self.server_name,
            upstream = %upstream_key,
            waf_rules = %upstream.waf_rules,
            "Routing request"
        );

        // Создаем peer для upstream
        let backend_addr = upstream.addrs.first()
            .expect("No backend addresses configured");
            
        let peer = HttpPeer::new(
            backend_addr.clone(),
            upstream.use_tls,
            upstream.sni.clone(),
        );
        
        Ok(Box::new(peer))
    }

    /// Фильтр запроса - первый этап обработки
    /// Выполняет проверку rate limit и WAF для заголовков и URI
    #[instrument(
        skip(self, session, ctx),
        fields(
            host = ?session.req_header().headers.get("host"),
            method = ?session.req_header().method,
            uri = ?session.req_header().uri,
            client_addr = ?session.client_addr()
        )
    )]
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> pingora::Result<bool> {
        let request_headers = session.req_header();
        
        let client_ip = session
            .client_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        // Создаем контекст если его нет
        if ctx.is_none() {
            *ctx = Some(RequestContext::new(&client_ip));
        }
        
        let context = ctx.as_mut().unwrap();
        
        // Очищаем контекст для нового запроса
        context.body_inspector.clear();
        context.violations.clear();
        
        let host_header = request_headers
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_lowercase();

        // Определяем upstream
        let (upstream_key, _upstream) = match self.get_upstream_key_and_config_for_host(&host_header) {
            Some((key, upstream)) => (key, upstream),
            None => {
                warn!(host = %host_header, "Unknown upstream for host");
                session.respond_error(404).await?;
                return Ok(true); // Запрос обработан (отправлен ответ)
            }
        };

        context.upstream_name = Some(upstream_key.clone());

        // Проверяем server rate limit
        if self.check_server_rate_limit(context).await? {
            session.respond_error(429).await?;
            return Ok(true);
        }

        // Проверяем upstream rate limit
        if self.check_rate_limit(context).await? {
            session.respond_error(429).await?;
            return Ok(true);
        }

        // Получаем WAF движок для upstream
        let waf = match self.waf_engines.get(upstream_key) {
            Some(waf) => waf,
            None => {
                error!(upstream = %upstream_key, "No WAF configured for upstream");
                session.respond_error(500).await?;
                return Ok(true);
            }
        };

        let method = request_headers.method.as_str();
        let uri = request_headers.uri.to_string();

        // Преобразуем заголовки в формат для WAF
        let mut headers_map = HMap::new();
        for (name, value) in request_headers.headers.iter() {
            headers_map.insert(name.clone(), value.clone());
        }

        // Проверяем WAF на заголовках и URI
        let waf_result = waf.check_detailed(&headers_map, &uri, &method, None);

        debug!(
            upstream = %upstream_key,
            method = %method,
            uri = %uri,
            client_ip = %client_ip,
            "WAF header check"
        );

        if !waf_result.allowed {
            warn!(
                target: "attack",
                upstream = %upstream_key,
                method = %method,
                uri = %uri,
                rule_id = %waf_result.rule_id,
                reason = %waf_result.reason,
                "WAF blocked request (headers/URI)"
            );
            
            context.violations.push(WafViolation {
                rule_id: waf_result.rule_id,
                reason: waf_result.reason.clone(),
                blocked: true,
                timestamp: Utc::now(),
                source: "header".to_string(),
            });
            
            session.respond_error(403).await?;
            return Ok(true);
        }

        debug!(
            upstream = %upstream_key,
            method = %method,
            uri = %uri,
            "Request headers passed WAF check"
        );
        
        Ok(false) // Продолжаем обработку запроса
    }

    /// Фильтр тела запроса - проверка WAF на содержимом тела
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        let context = match ctx {
            Some(ctx) => ctx,
            None => {
                warn!("No context for body inspection");
                return Ok(());
            }
        };

        let upstream_name = match &context.upstream_name {
            Some(name) => name,
            None => {
                warn!("No upstream determined for body inspection");
                return Ok(());
            }
        };

        let waf = match self.waf_engines.get(upstream_name) {
            Some(waf) => waf,
            None => {
                error!(upstream = %upstream_name, "No WAF configured for body inspection");
                return Ok(());
            }
        };

        // Накопливаем чанки тела запроса
        if let Some(chunk) = body {
            if let Err(e) = context.body_inspector.append_chunk(chunk) {
                error!(
                    upstream = %upstream_name,
                    client_ip = %context.client_ip,
                    "Body size limit exceeded: {}", e
                );
                
                context.violations.push(WafViolation {
                    rule_id: 413,
                    reason: format!("Body size limit exceeded: {}", e),
                    blocked: true,
                    timestamp: Utc::now(),
                    source: "body".to_string(),
                });
                
                session.respond_error(413).await?;
                return Err(pingora::Error::new_str("Body size limit exceeded"));
            }
        }

        // Когда все чанки получены (end_of_stream = true), проверяем полное тело
        if end_of_stream {
            let full_body = context.body_inspector.get_body();
            
            if !full_body.is_empty() {
                let request_headers = session.req_header();
                let method = request_headers.method.as_str();
                let uri = request_headers.uri.to_string();

                let mut headers_map = HMap::new();
                for (name, value) in request_headers.headers.iter() {
                    headers_map.insert(name.clone(), value.clone());
                }

                // Проверяем WAF на полном теле запроса
                let waf_result = waf.check_detailed(
                    &headers_map, 
                    &uri, 
                    &method, 
                    Some(&full_body)
                );

                debug!(
                    upstream = %upstream_name,
                    method = %method,
                    uri = %uri,
                    client_ip = %context.client_ip,
                    body_size = full_body.len(),
                    "WAF body check"
                );

                if !waf_result.allowed {
                    warn!(
                        target: "attack",
                        upstream = %upstream_name,
                        method = %method,
                        uri = %uri,
                        client_ip = %context.client_ip,
                        body_size = full_body.len(),
                        rule_id = %waf_result.rule_id,
                        reason = %waf_result.reason,
                        "WAF blocked request body"
                    );
                    
                    context.violations.push(WafViolation {
                        rule_id: waf_result.rule_id,
                        reason: waf_result.reason.clone(),
                        blocked: true,
                        timestamp: Utc::now(),
                        source: "body".to_string(),
                    });
                    
                    *body = None; // Очищаем тело

                    // Отправляем ответ об ошибке
                    session.as_downstream();
                    session.respond_error(403).await?;
                    return Ok(());
                }

                debug!(
                    upstream = %upstream_name,
                    method = %method,
                    uri = %uri,
                    body_size = full_body.len(),
                    "Request body passed WAF check"
                );
            } else {
                debug!(
                    upstream = %upstream_name,
                    client_ip = %context.client_ip,
                    "Empty request body, skipping WAF check"
                );
            }
        }

        Ok(())
    }

    /// Фильтр ответа - добавляет заголовки rate limit
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        if let Some(context) = ctx {
            if let (Some(remaining), Some(limit)) = (context.rate_limit_remaining, context.rate_limit_limit) {
                // Удаляем существующие заголовки
                upstream_response.remove_header("x-ratelimit-limit");
                upstream_response.remove_header("x-ratelimit-remaining");
                upstream_response.remove_header("x-ratelimit-reset");
                
                // Добавляем новые заголовки rate limit
                upstream_response.append_header("X-RateLimit-Limit", &limit.to_string())?;
                upstream_response.append_header("X-RateLimit-Remaining", &remaining.to_string())?;
                upstream_response.append_header("X-RateLimit-Reset", "60")?;
            }
        }
        Ok(())
    }
}

/// Запускает прокси сервер
pub fn run_server(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    // Записываем PID для управления процессом
    crate::utils::pid::write_pid("/tmp/centaur.pid")?;

    let proxy_manager = Arc::new(ProxyManager::new(config.clone()));

    let pingora_opt = build_pingora_opt_from_config(&config);
    let mut server = pingora::server::Server::new(Some(pingora_opt)).unwrap();

    let is_upgrade = config.is_upgrade();

    server.bootstrap();

    // Регистрируем все сервисы из конфигурации
    for (name, cfg) in config.get_servers() {
        // Пропускаем отключенные серверы
        if !cfg.enabled {
            tracing::info!("Server {} disabled, skipping", name);
            continue;
        }

        let proxy = proxy_manager
            .get_proxy(&name)
            .ok_or_else(|| format!("Proxy not found for server: {}", name))?;

        let mut svc = pingora::proxy::http_proxy_service(&server.configuration, proxy.as_ref().clone());

        svc.add_tcp(&cfg.addr);
        server.add_service(svc);
    }

    // Запускаем Admin API только если не в режиме upgrade
    if !is_upgrade { 
        let admin_port = config.get_admin_port(); 
        info!("Spawning Admin API process on {}", admin_port); 
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap()); 
        cmd.arg("run-admin") 
            .arg("--port") 
            .arg(admin_port.to_string()); 
        cmd.spawn().expect("Failed to spawn admin API process"); 
    } else { 
        info!("Admin API disabled (upgrade mode)"); 
    }

    tracing::info!("Pingora running...");
    server.run_forever();
}