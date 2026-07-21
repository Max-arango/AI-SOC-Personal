//! Configuration schema definitions and validation

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JSON Schema for configuration validation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConfigSchema {
    pub module: String,
    pub version: u32,
    pub schema: serde_json::Value,
}

/// Generate JSON Schema for a type
pub fn generate_schema<T: JsonSchema>() -> serde_json::Value {
    let schema = schemars::schema_for!(T);
    serde_json::to_value(schema).unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
}

/// Validate a TOML string against a JSON Schema.
///
/// NOTE: Full JSON-Schema validation is currently a thin pass that only ensures
/// the input is well-formed TOML. Deep schema validation can be layered on top
/// later without changing this signature.
pub fn validate_against_schema(toml_str: &str, _schema: &serde_json::Value) -> Result<(), Vec<String>> {
    let value: toml::Value = toml_str.parse()
        .map_err(|e| vec![format!("TOML parse error: {}", e)])?;

    let _ = toml_to_json(&value);
    Ok(())
}

fn toml_to_json(value: &toml::Value) -> serde_json::Value {
    match value {
        toml::Value::String(s) => serde_json::Value::String(s.clone()),
        toml::Value::Integer(i) => serde_json::Value::Number(serde_json::Number::from(*i)),
        toml::Value::Float(f) => serde_json::Value::Number(serde_json::Number::from_f64(*f).unwrap_or(serde_json::Number::from(0))),
        toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
        toml::Value::Datetime(dt) => serde_json::Value::String(dt.to_string()),
        toml::Value::Array(arr) => serde_json::Value::Array(arr.iter().map(toml_to_json).collect()),
        toml::Value::Table(table) => {
            let mut map = serde_json::Map::new();
            for (k, v) in table {
                map.insert(k.clone(), toml_to_json(v));
            }
            serde_json::Value::Object(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use schemars::JsonSchema;
    
    #[derive(Debug, Serialize, Deserialize, JsonSchema)]
    struct TestConfig {
        name: String,
        port: u16,
        enabled: bool,
    }
    
    #[test]
    fn test_schema_generation() {
        let schema = generate_schema::<TestConfig>();
        assert!(schema.is_object());
    }
    
    #[test]
    fn test_validation() {
        let schema = generate_schema::<TestConfig>();
        
        let valid = r#"
            name = "test"
            port = 8080
            enabled = true
        "#;
        assert!(validate_against_schema(valid, &schema).is_ok());
        
        let invalid = r#"
            name = "test"
            port = "not a number"
            enabled = true
        "#;
        assert!(validate_against_schema(invalid, &schema).is_err());
    }
}