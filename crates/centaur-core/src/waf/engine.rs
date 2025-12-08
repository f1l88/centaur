use crate::waf::parser::{load_toml_rules, ParsedRule};
use crate::waf::operator::{check_operator, operator_desc};

use pingora::http::HMap;
use std::{path::Path};

#[derive(Debug, Clone)]
pub struct WafCheckResult {
    pub allowed: bool,
    pub matched_rule: Option<ParsedRule>,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    pub reason: String,
    pub rule_id: u32,
    pub msg: Option<String>,
}

#[derive(Clone)]
pub struct Engine {
    pub rules: Vec<ParsedRule>,
}

impl Engine {
    /// Загружает TOML-файл содержащий [[rule]]
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let rules = load_toml_rules(path.as_ref())?;
        println!("✅ Загружено {} WAF правил", rules.len());
        Ok(Self { rules })
    }

    pub fn check(&self, request_line: &str, headers: &HMap, uri: &str) -> bool {
        self.check_detailed(request_line, headers, uri).allowed
    }

    pub fn check_detailed(&self, request_line: &str, headers: &HMap, uri: &str) -> WafCheckResult {
        for rule in &self.rules {
            let mut matched = false;
            let mut reason = String::new();
            let mut target_value = String::new();
            let mut target_name = String::new();
            let _msg = String::new();

            // ----------------------------
            // REQUEST_HEADERS:NAME
            // ----------------------------
            if rule.variable.starts_with("REQUEST_HEADERS:") {
                if let Some((_, header_name)) = rule.variable.split_once(':') {
                    let key = header_name.to_ascii_lowercase();

                    if let Some(value) = headers.get(&key) {
                        let header_value = value.to_str().unwrap_or_default();

                        target_name = header_name.to_string();
                        target_value = header_value.to_string();

                        let v = header_value.to_ascii_lowercase();
                        let arg = rule.pattern.to_ascii_lowercase();

                        matched = check_operator(&rule.operator, &v, &arg);

                        if matched {
                            reason = format!(
                                "header '{}' {} '{}'",
                                header_name,
                                operator_desc(&rule.operator),
                                rule.pattern
                            );
                        }
                    }
                }
            }
            // ----------------------------
            // REQUEST_URI
            // ----------------------------
            else if rule.variable == "REQUEST_URI" {
                target_name = "URI".into();
                target_value = uri.into();

                let v = uri.to_ascii_lowercase();
                let arg = rule.pattern.to_ascii_lowercase();

                matched = check_operator(&rule.operator, &v, &arg);


                if matched {
                    reason = format!(
                        "URI {} '{}'",
                        operator_desc(&rule.operator),
                        rule.pattern
                    );
                }
            }

            else if rule.variable == "REQUEST_LINE" {
                target_value = request_line.to_string();
                target_name = "REQUEST_LINE".to_string();

                let v = request_line.to_ascii_lowercase();
                let arg = rule.pattern.to_ascii_lowercase();

                matched = check_operator(&rule.operator, &v, &arg);

                if matched {
                    reason = format!(
                        "REQUEST_LINE {} '{}'",
                        operator_desc(&rule.operator),
                        rule.pattern
                    );
                }
            }


            // Если правило сработало
            if matched {
                let is_blocking = rule.actions.get("action")
                    == Some(&"deny".to_string());

                return WafCheckResult {
                    allowed: !is_blocking,
                    matched_rule: Some(rule.clone()),
                    header_name: Some(target_name),
                    header_value: Some(target_value),
                    reason,
                    rule_id: rule.id,
                    msg: rule.msg.clone(),
                };
            }
        }

        // Ни одно правило не сработало
        WafCheckResult {
            allowed: true,
            matched_rule: None,
            header_name: None,
            header_value: None,
            reason: "Ни одно правило не сработало".to_string(),
            rule_id: 0,
            msg: Some("".to_owned()),
        }
    }

    // ----------------------------
    // OPERATORS
    // ----------------------------
    // fn check_operator(op: &str, value: &str, argument: &str) -> bool {
    //     match op.to_lowercase().as_str() {
    //         "contains" | "pm" => value.contains(argument),
    //         "streq" => value == argument,
    //         "rx" => regex::Regex::new(argument)
    //             .map(|r| r.is_match(value))
    //             .unwrap_or(false),
    //         _ => false,
    //     }
    // }

    // fn operator_desc(operator: &str) -> &'static str {
    //     match operator.to_lowercase().as_str() {
    //         "contains" | "pm" => "содержит",
    //         "streq" => "равно",
    //         "rx" => "совпадает с regex",
    //         _ => "проверяется по",
    //     }
    // }

    // ----------------------------
    // INFO
    // ----------------------------
    pub fn get_rules_info(&self) -> String {
        let total = self.rules.len();

        let blocking = self.rules
            .iter()
            .filter(|r| r.actions.get("action") == Some(&"deny".to_string()))
            .count();

        let uri_rules = self.rules
            .iter()
            .filter(|r| r.variable == "REQUEST_URI")
            .count();

        let header_rules = self.rules
            .iter()
            .filter(|r| r.variable.starts_with("REQUEST_HEADERS:"))
            .count();

        format!(
            "Всего правил: {} (блокирующих: {}, логгируемых: {})\n\
             Правил URI: {}, Правил заголовков: {}",
            total,
            blocking,
            total - blocking,
            uri_rules,
            header_rules
        )
    }
}
