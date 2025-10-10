use std::{fs, path::Path};
use crate::waf::parser::{ParsedRule, parse_secrule};
use pingora::http::HMap;


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
        Ok(Self { rules })
    }

    pub fn check(&self, headers: &HMap) -> bool {
        for rule in &self.rules {
            if rule.variable.starts_with("REQUEST_HEADERS:") {
                if let Some((_, header_name)) = rule.variable.split_once(':') {
                    let key = header_name.to_ascii_lowercase();
                    if let Some(value) = headers.get(&key) {
                        let v = value.to_str().unwrap_or_default().to_ascii_lowercase();
                        let arg = rule.argument.to_ascii_lowercase();

                        match rule.operator.as_str() {
                            "contains" | "pm" => {
                                if v.contains(&arg) && rule.actions.contains_key("deny") {
                                    return false;
                                }
                            }
                            "streq" => {
                                if v == arg && rule.actions.contains_key("deny") {
                                    return false;
                                }
                            }
                            "rx" => {
                                if let Ok(re) = regex::Regex::new(&rule.argument) {
                                    if re.is_match(&v) && rule.actions.contains_key("deny") {
                                        return false;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        true
    }
}
