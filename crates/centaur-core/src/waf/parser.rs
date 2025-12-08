use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct TomlRule {
    pub id: u32,
    pub phase: u32,

    /// Один variable (REQUEST_URI) или "REQUEST_HEADERS:User-Agent"
    pub variables: String,

    /// оператор: streq, rx, contains, pm и т. д.
    pub operators: String,

    /// аргумент оператора
    pub pattern: String,

    /// "deny", "allow" и т.д.
    pub actions: String,

    /// HTTP статус если deny
    #[serde(default)]
    pub status: Option<u16>,

    /// сообщение
    #[serde(default)]
    pub msg: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TomlRulesFile {
    pub rule: Vec<TomlRule>,
}

#[derive(Debug, Clone)]
pub struct ParsedRule {
    pub id: u32,
    pub phase: u8,
    pub variable: String,
    pub operator: String,
    pub pattern: String,
    pub actions: HashMap<String, String>,
    pub msg: Option<String>,
}

pub fn load_toml_rules(path: &std::path::Path) -> anyhow::Result<Vec<ParsedRule>> {
    let content = std::fs::read_to_string(path)?;
    let parsed: TomlRulesFile = toml::from_str(&content)?;

    let mut out = Vec::new();

    for r in parsed.rule {
        let mut actions = HashMap::new();

        // основной action
        actions.insert("action".into(), r.actions.clone());

        // дополнительные параметры
        if let Some(ref msg) = r.msg {
            actions.insert("msg".into(), msg.clone());
        }
        if let Some(status) = r.status {
            actions.insert("status".into(), status.to_string());
        }

        // формируем ParsedRule
        out.push(ParsedRule {
            id: r.id,
            variable: r.variables,
            operator: r.operators,
            pattern: r.pattern,
            actions,
            phase: r.phase as u8,
            msg: r.msg,
        });
    }

    Ok(out)
}
