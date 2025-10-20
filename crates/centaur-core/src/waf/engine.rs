use crate::waf::parser::{parse_secrule, ParsedRule};
use pingora::http::HMap;
use std::{fs, path::Path};

#[derive(Debug, Clone)]
pub struct WafCheckResult {
    pub allowed: bool,
    pub matched_rule: Option<ParsedRule>,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    pub reason: String,
    pub rule_id: u32,
}

#[derive(Clone)]
pub struct Engine {
    pub rules: Vec<ParsedRule>,
}

impl Engine {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut rules = Vec::new();
        for (i, line) in content.lines().enumerate() {
            if let Some(rule) = parse_secrule(line) {
                rules.push(rule);
            } else if !line.trim().is_empty() && !line.starts_with('#') {
                eprintln!("⚠️  Skipped invalid rule at line {}: {}", i + 1, line);
            }
        }
        println!("✅ Загружено {} WAF правил", rules.len());
        Ok(Self { rules })
    }

    pub fn check(&self, headers: &HMap, uri: &str) -> bool {
        self.check_detailed(headers, uri).allowed
    }

    pub fn check_detailed(&self, headers: &HMap, uri: &str) -> WafCheckResult {
        for rule in &self.rules {
            let mut matched = false;
            let mut match_reason = String::new();
            let mut target_value = String::new();
            let mut target_name = String::new();

            // Проверка REQUEST_HEADERS
            if rule.variable.starts_with("REQUEST_HEADERS:") {
                if let Some((_, header_name)) = rule.variable.split_once(':') {
                    let key = header_name.to_ascii_lowercase();
                    if let Some(value) = headers.get(&key) {
                        let header_value = value.to_str().unwrap_or_default();
                        target_value = header_value.to_string();
                        target_name = header_name.to_string();

                        let v = header_value.to_ascii_lowercase();
                        let arg = rule.argument.to_ascii_lowercase();

                        matched = Self::check_operator(&rule.operator, &v, &arg);
                        if matched {
                            match_reason = format!(
                                "header '{}' {} '{}'",
                                header_name,
                                Self::get_operator_description(&rule.operator),
                                rule.argument
                            );
                        }
                    }
                }
            }
            // Проверка REQUEST_URI
            else if rule.variable == "REQUEST_URI" {
                target_value = uri.to_string();
                target_name = "URI".to_string();

                let v = uri.to_ascii_lowercase();
                let arg = rule.argument.to_ascii_lowercase();

                matched = Self::check_operator(&rule.operator, &v, &arg);
                if matched {
                    match_reason = format!(
                        "URI {} '{}'",
                        Self::get_operator_description(&rule.operator),
                        rule.argument
                    );
                }
            }

            if matched {
                let is_blocking = rule.actions.contains_key("deny");
                let action = if is_blocking {
                    "БЛОКИРОВКА"
                } else {
                    "ЛОГИРОВАНИЕ"
                };

                return WafCheckResult {
                    allowed: !is_blocking,
                    matched_rule: Some(rule.clone()),
                    header_name: Some(target_name),
                    header_value: Some(target_value),
                    reason: format!("{}: {}", action, match_reason),
                    rule_id: rule.id,
                };
            }
        }

        // Если ни одно правило не сработало
        WafCheckResult {
            allowed: true,
            matched_rule: None,
            header_name: None,
            header_value: None,
            reason: "Ни одно правило не сработало".to_string(),
            rule_id: 0,
        }
    }

    fn check_operator(operator: &str, value: &str, argument: &str) -> bool {
        match operator.to_lowercase().as_str() {
            "contains" | "pm" => value.contains(argument),
            "streq" => value == argument,
            "rx" => {
                if let Ok(re) = regex::Regex::new(argument) {
                    re.is_match(value)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn get_operator_description(operator: &str) -> &'static str {
        match operator.to_lowercase().as_str() {
            "contains" | "pm" => "содержит",
            "streq" => "равно",
            "rx" => "совпадает с regex",
            _ => "проверяется по",
        }
    }

    pub fn get_rules_info(&self) -> String {
        let total = self.rules.len();
        let blocking_rules = self
            .rules
            .iter()
            .filter(|r| r.actions.contains_key("deny"))
            .count();
        let logging_rules = total - blocking_rules;

        let uri_rules = self
            .rules
            .iter()
            .filter(|r| r.variable == "REQUEST_URI")
            .count();
        let header_rules = self
            .rules
            .iter()
            .filter(|r| r.variable.starts_with("REQUEST_HEADERS:"))
            .count();

        format!("Всего правил: {} (блокирующих: {}, логирующих: {})\nПравил URI: {}, Правил заголовков: {}",
                total, blocking_rules, logging_rules, uri_rules, header_rules)
    }
}
