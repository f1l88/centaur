use modsecurity::{ModSecurity, Rules};
use pingora::http::HMap;
use std::{fs, path::Path};
use tracing::info;

#[derive(Debug, Clone)]
pub struct WafCheckResult {
    pub allowed: bool,
    pub matched_rule: Option<String>,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    pub reason: String,
    pub rule_id: u32,
}

pub struct Engine {
    ms: ModSecurity,
    rules: Rules,
}

impl Engine {
    /// Загружает правила ModSecurity из файла
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let rules_text = fs::read_to_string(&path)?;
        let ms = ModSecurity::default();

        let mut rules = Rules::new();
        rules
            .add_plain(&rules_text)
            .map_err(|e| anyhow::anyhow!("Ошибка загрузки правил: {e}"))?;

        info!("Правила ModSecurity успешно загружены из: {}", path.as_ref().display());
        Ok(Self { ms, rules })
    }

    /// Основной метод проверки с поддержкой query string
    pub fn check_detailed(&self, headers: &HMap, uri: &str, method: &str, body: Option<&[u8]>) -> WafCheckResult {
        let mut tx = match self.ms.transaction_builder().with_rules(&self.rules).with_logging(|msg| {
            if let Some(msg) = msg {
                println!("Received log: {}", msg);
            }
        }).build() {
            Ok(tx) => tx,
            Err(e) => {
                return WafCheckResult {
                    allowed: true,
                    matched_rule: None,
                    header_name: None,
                    header_value: None,
                    reason: format!("Ошибка создания транзакции: {e}"),
                    rule_id: 0,
                }
            }
        };

        // 1. Обрабатываем URI (включая query string)
        if let Err(e) = tx.process_uri(uri, method, "1.1") {
            return WafCheckResult {
                allowed: true,
                matched_rule: None,
                header_name: None,
                header_value: None,
                reason: format!("Ошибка process_uri: {e}"),
                rule_id: 0,
            };
        }

        // 2. Добавляем заголовки
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                if let Err(e) = tx.add_request_header(&name.to_string(), v) {
                    eprintln!("Ошибка добавления заголовка {}: {}", name, e);
                }
            }
        }

        // 3. Обрабатываем заголовки
        if let Err(e) = tx.process_request_headers() {
            return WafCheckResult {
                allowed: true,
                matched_rule: None,
                header_name: None,
                header_value: None,
                reason: format!("Ошибка process_request_headers: {e}"),
                rule_id: 0,
            };
        }

        // 4. Обрабатываем тело запроса (если есть)
        if let Some(body_data) = body {
            if !body_data.is_empty() {
                if let Err(e) = tx.append_request_body(body_data) {
                    return WafCheckResult {
                        allowed: true,
                        matched_rule: None,
                        header_name: None,
                        header_value: None,
                        reason: format!("Ошибка append_request_body: {e}"),
                        rule_id: 0,
                    };
                }
            }
        }

        // 5. Завершаем обработку тела
        if let Err(e) = tx.process_request_body() {
            return WafCheckResult {
                allowed: true,
                matched_rule: None,
                header_name: None,
                header_value: None,
                reason: format!("Ошибка process_request_body: {e}"),
                rule_id: 0,
            };
        }

        match tx.intervention() {
            Some(intervention) => {
                let status = intervention.status();
                let message = intervention.log()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("Blocked with status {}", status));
                
                WafCheckResult {
                    allowed: false,
                    matched_rule: Some(message.clone()),
                    header_name: None,
                    header_value: None,
                    reason: format!("Blocked: {}", message),
                    rule_id: status as u32,
                }
            }
            None => {
                    // Нет intervention - разрешаем
                    WafCheckResult {
                        allowed: true,
                        matched_rule: None,
                        header_name: None,
                        header_value: None,
                        reason: "Allowed by WAF".to_string(),
                        rule_id: 0,
                    }
                }
            }
        }

        /// Информация о правилах
        pub fn get_rules_info(&self) -> String {
            "Правила ModSecurity загружены".to_string()
        }
    }

    // Упрощённая проверка
    // pub fn check(&self, headers: &HMap, uri: &str, method: &str, body: Option<&[u8]>) -> bool {
    //     self.check_detailed(headers, uri, method, body).allowed
    // }

