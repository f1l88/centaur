use modsecurity::{ModSecurity, Rules};
use pingora::http::HMap;
use std::{fs, path::Path};

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
    /// Загружает правила ModSecurity из файла (например `rules/example.conf`)
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let rules_text = fs::read_to_string(&path)?;
        let ms = ModSecurity::default();

        let mut rules = Rules::new();
        rules
            .add_plain(&rules_text)
            .map_err(|e| anyhow::anyhow!("Ошибка загрузки правил: {e}"))?;

        println!("✅ Правила ModSecurity успешно загружены из: {}", path.as_ref().display());
        Ok(Self { ms, rules })
    }

    /// Основной метод проверки (совместим с прежним API)
    pub fn check_detailed(&self, headers: &HMap, uri: &str) -> WafCheckResult {
        let mut tx = match self.ms.transaction_builder().with_rules(&self.rules).build() {
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

        // Метод и версия по умолчанию
        let method = "GET";
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

        // Передаём заголовки - преобразуем HeaderName в строку
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                // Преобразуем HeaderName в строку с помощью to_string()
                if let Err(e) = tx.add_request_header(&name.to_string(), v) {
                    eprintln!("Ошибка добавления заголовка {}: {}", name, e);
                }
            }
        }

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

        // Проверяем, было ли вмешательство (intervention)
        if let Some(intervention) = tx.intervention() {
            let status = intervention.status();
            
            // Получаем сообщение из лога, как в примере
            let message = if let Some(log) = intervention.log() {
                log.to_string()
            } else {
                format!("Блокировка ModSecurity с кодом {}", status)
            };

            return WafCheckResult {
                allowed: false,
                matched_rule: Some(message.clone()),
                header_name: None,
                header_value: None,
                reason: format!("Блокировка ModSecurity: {}", message),
                rule_id: status as u32,
            };
        }

        // Если всё прошло успешно
        WafCheckResult {
            allowed: true,
            matched_rule: None,
            header_name: None,
            header_value: None,
            reason: "Разрешено ModSecurity".into(),
            rule_id: 0,
        }
    }

    /// Упрощённая проверка (true = разрешено)
    pub fn check(&self, headers: &HMap, uri: &str) -> bool {
        self.check_detailed(headers, uri).allowed
    }

    /// Информация о текущем наборе правил
    pub fn get_rules_info(&self) -> String {
        "Правила ModSecurity загружены".to_string()
    }
}