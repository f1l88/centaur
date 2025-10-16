use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ParsedRule {
    #[allow(dead_code)]
    pub id: u32,
    pub variable: String,
    pub operator: String,
    pub argument: String,
    pub actions: HashMap<String, String>,
}

pub fn parse_secrule(line: &str) -> Option<ParsedRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let re = Regex::new(r#"(?i)^SecRule\s+([^\s]+)\s+"?@?([a-zA-Z0-9_]+)\s+([^"]+)"?\s+"?(.+)"?"#).unwrap();
    let caps = re.captures(line)?;
    let variable = caps.get(1)?.as_str().to_string();
    let operator = caps.get(2)?.as_str().to_string();
    let argument = caps.get(3)?.as_str().to_string();
    let actions_str = caps.get(4)?.as_str();

    let mut actions = HashMap::new();
    for part in actions_str.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some((k, v)) = p.split_once(':') {
            actions.insert(k.to_string(), v.trim_matches('\'').to_string());
        } else {
            actions.insert(p.to_string(), String::new());
        }
    }

    let id = actions.get("id").and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

    Some(ParsedRule { id, variable, operator, argument, actions })
}
