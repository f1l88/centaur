// src/operator.rs
pub fn check_operator(operator: &str, value: &str, argument: &str) -> bool {
    match operator.to_lowercase().as_str() {
        "contains" | "pm" => value.contains(argument),
        "streq" => value == argument,
        "beginswith" => value.starts_with(argument),
        "!beginswith" => !value.starts_with(argument),

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


pub fn operator_desc(operator: &str) -> &'static str {
    match operator.to_lowercase().as_str() {
            "contains" | "pm" => "содержит",
            "streq" => "равно",
            "beginswith" => "начинается с",
            "!beginswith" => "не начинается с",
            "rx" => "совпадает с regex",
            _ => "проверяется по",
    }
}
