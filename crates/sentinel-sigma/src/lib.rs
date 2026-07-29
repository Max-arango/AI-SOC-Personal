use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub status: String,
    pub description: Option<String>,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub date: String,
    pub tags: Option<Vec<String>>,
    pub logsource: Option<SigmaLogSource>,
    pub detection: SigmaDetection,
    #[serde(default)]
    pub falsepositives: Option<Vec<serde_yaml::Value>>,
    pub level: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SigmaLogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SigmaDetection {
    #[serde(flatten)]
    pub fields: HashMap<String, serde_yaml::Value>,
    pub condition: String,
}

#[derive(Debug, Serialize)]
pub struct SentinelRule {
    pub rule: SentinelRuleInner,
}

#[derive(Debug, Serialize)]
pub struct SentinelRuleInner {
    pub id: String,
    pub version: u32,
    pub name: String,
    pub description: String,
    pub author: String,
    pub created: String,
    pub modified: String,
    pub enabled: bool,
    pub category: String,
    pub subcategory: Option<String>,
    pub mitre: Vec<SentinelMitreMapping>,
    pub severity: String,
    pub risk: SentinelRisk,
    pub condition: String,
    #[serde(default)]
    pub and_conditions: Vec<String>,
    #[serde(default)]
    pub or_conditions: Vec<String>,
    #[serde(default)]
    pub not_conditions: Vec<String>,
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
    #[serde(default)]
    pub suppressions: Vec<serde_json::Value>,
    #[serde(default)]
    pub tests: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct SentinelMitreMapping {
    pub technique: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Debug, Serialize)]
pub struct SentinelRisk {
    pub base_score: u32,
    pub confidence: f64,
    #[serde(default)]
    pub multipliers: Vec<serde_json::Value>,
}

fn map_logsource_to_event_type(logsource: &Option<SigmaLogSource>) -> String {
    let ls = match logsource {
        Some(l) => l,
        None => return "sentinel.process.create".into(),
    };

    match ls.category.as_deref() {
        Some("process_creation") => "sentinel.process.create",
        Some("network_connection") => "sentinel.network.connect",
        Some("file_event") | Some("file_change") => "sentinel.file.modify",
        Some("registry_event") | Some("registry_add") | Some("registry_delete") => "sentinel.registry.set_value",
        Some("dns_query") => "sentinel.network.connect",
        Some("image_load") => "sentinel.process.create",
        Some("pipe_created") => "sentinel.process.create",
        Some("wmi_event") => "sentinel.process.create",
        Some("create_remote_thread") => "sentinel.process.inject",
        Some("driver_load") => "sentinel.process.create",
        _ => "sentinel.process.create",
    }.into()
}

fn map_level_to_severity(level: &Option<String>) -> (&str, u32) {
    match level.as_deref() {
        Some("critical") => ("Critical", 90),
        Some("high") => ("Error", 75),
        Some("medium") => ("Warning", 55),
        Some("low") => ("Notice", 35),
        Some("informational") => ("Info", 20),
        _ => ("Warning", 50),
    }
}

fn map_sigma_field_to_cel(field: &str, operand: &str, value: &str) -> Option<String> {
    let cel_field = match field {
        "Image" => "event.process.name",
        "CommandLine" => "event.process.command_line",
        "ParentImage" => "event.process.name",
        "ParentCommandLine" => "event.process.command_line",
        "ProcessId" => "event.process.pid",
        "DestinationIp" | "dst_ip" => "event.network.remote_addr",
        "DestinationPort" | "dst_port" => "event.network.remote_port",
        "SourceIp" | "src_ip" => "event.network.local_addr",
        "SourcePort" | "src_port" => "event.network.local_port",
        "TargetFilename" | "ImagePath" => "event.process.path",
        "User" => "event.process.user.username",
        "OriginalFileName" => "event.process.name",
        "Description" => "event.process.name",
        "Company" => "event.process.name",
        "Product" => "event.process.name",
        "Signature" => "event.process.signing.is_signed",
        "IntegrityLevel" => "event.process.integrity_level",
        _ => return None,
    };

    match operand {
        "contains" => {
            let val = value.trim_matches('\'');
            Some(format!("{}.contains(\"{}\")", cel_field, val))
        }
        "endswith" => {
            let val = value.trim_matches('\'');
            Some(format!("{}.contains(\"{}\")", cel_field, val))
        }
        "startswith" => {
            let val = value.trim_matches('\'');
            Some(format!("{}.contains(\"{}\")", cel_field, val))
        }
        _ => {
            let val = value.trim_matches('\'');
            if val == "true" || val == "false" {
                Some(format!("{} == {}", cel_field, val))
            } else if let Ok(_n) = val.parse::<i64>() {
                Some(format!("{} == {}", cel_field, val))
            } else {
                Some(format!("{}.contains(\"{}\")", cel_field, val))
            }
        }
    }
}

fn build_cel_condition(detection: &SigmaDetection) -> String {
    let condition = &detection.condition;
    let parts: Vec<&str> = condition
        .split(|c: char| c == ' ' || c == '(' || c == ')' || c == '&')
        .filter(|p| !p.is_empty() && *p != "|" && *p != "not" && *p != "1" && *p != "of")
        .collect();

    let mut cel_parts = Vec::new();
    for part in &parts {
        let clean = part.trim_matches(|c: char| c.is_whitespace() || c == '(' || c == ')');
        if clean.is_empty() || clean == "and" || clean == "or" || clean == "not" {
            continue;
        }

        if let Some(sel_map) = detection.fields.get(clean) {
            if let Some(sel) = sel_map.as_mapping() {
                let mut sub_conditions = Vec::new();
                for (field_key, field_val) in sel {
                    let field_name = field_key.as_str().unwrap_or("");
                    let parts: Vec<&str> = field_name.split('|').collect();
                    let field = parts[0];
                    let operand = if parts.len() > 1 { parts[1] } else { "contains" };

                    match field_val {
                        serde_yaml::Value::String(s) => {
                            if let Some(cel) = map_sigma_field_to_cel(field, operand, s) {
                                sub_conditions.push(cel);
                            }
                        }
                        serde_yaml::Value::Sequence(vals) => {
                            let mut or_conds = Vec::new();
                            for v in vals {
                                if let Some(s) = v.as_str() {
                                    if let Some(cel) = map_sigma_field_to_cel(field, operand, s) {
                                        or_conds.push(cel);
                                    }
                                }
                            }
                            if !or_conds.is_empty() {
                                sub_conditions.push(format!("({})", or_conds.join(" || ")));
                            }
                        }
                        _ => {}
                    }
                }
                if !sub_conditions.is_empty() {
                    cel_parts.push(format!("({})", sub_conditions.join(" && ")));
                }
            }
        }
    }

    if cel_parts.is_empty() {
        String::new()
    } else {
        cel_parts.join(" && ")
    }
}

fn map_mitre_tags(tags: &[String]) -> Vec<SentinelMitreMapping> {
    let mut mappings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for tag in tags {
        if let Some(tech) = tag.strip_prefix("attack.t") {
            let tech_clean = tech.replace('.', ".");
            if seen.insert(tech_clean.clone()) {
                mappings.push(SentinelMitreMapping {
                    technique: tech_clean.clone(),
                    name: format!("Technique {}", tech_clean),
                    tactic: String::new(),
                });
            }
        }
    }

    let tactic_map: HashMap<&str, &str> = [
        ("t1059", "Execution"),
        ("t1203", "Execution"),
        ("t1204", "Execution"),
        ("t1569", "Execution"),
        ("t1547", "Persistence"),
        ("t1053", "Persistence"),
        ("t1543", "Persistence"),
        ("t1068", "Privilege Escalation"),
        ("t1548", "Privilege Escalation"),
        ("t1055", "Defense Evasion"),
        ("t1218", "Defense Evasion"),
        ("t1070", "Defense Evasion"),
        ("t1036", "Defense Evasion"),
        ("t1562", "Defense Evasion"),
        ("t1003", "Credential Access"),
        ("t1552", "Credential Access"),
        ("t1082", "Discovery"),
        ("t1083", "Discovery"),
        ("t1057", "Discovery"),
        ("t1016", "Discovery"),
        ("t1021", "Lateral Movement"),
        ("t1046", "Discovery"),
        ("t1135", "Discovery"),
        ("t1560", "Collection"),
        ("t1056", "Collection"),
        ("t1074", "Collection"),
        ("t1071", "Command and Control"),
        ("t1105", "Command and Control"),
        ("t1090", "Command and Control"),
        ("t1041", "Exfiltration"),
        ("t1048", "Exfiltration"),
        ("t1485", "Impact"),
        ("t1486", "Impact"),
        ("t1490", "Impact"),
    ]
    .iter()
    .cloned()
    .collect();

    for m in &mut mappings {
        let prefix = &m.technique.replace('.', "")[..m.technique.replace('.', "").len().min(4)];
        let search = format!("t{}", prefix);
        if let Some(tactic) = tactic_map.get(search.as_str()) {
            m.tactic = tactic.to_string();
        }
    }

    mappings
}

pub fn convert_sigma_to_sentinel(sigma: &SigmaRule) -> SentinelRule {
    let id = if sigma.id.is_empty() {
        format!("sigma-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0"))
    } else {
        sigma.id.clone()
    };

    let event_type = map_logsource_to_event_type(&sigma.logsource);
    let (severity, base_score) = map_level_to_severity(&sigma.level);
    let cel_condition = build_cel_condition(&sigma.detection);
    let tags = sigma.tags.as_deref().unwrap_or(&[]);
    let mitre = map_mitre_tags(tags);

    let full_condition = if cel_condition.is_empty() {
        format!("event.type == \"{}\"", event_type)
    } else {
        format!("event.type == \"{}\" && ({})", event_type, cel_condition)
    };

    let now = chrono::Utc::now().to_rfc3339();
    let description = sigma
        .description
        .clone()
        .unwrap_or_else(|| sigma.title.clone());

    SentinelRule {
        rule: SentinelRuleInner {
            id: format!("sigma-{}", id),
            version: 1,
            name: sigma.title.clone(),
            description,
            author: sigma.author.clone(),
            created: now.clone(),
            modified: now,
            enabled: sigma.status != "deprecated",
            category: mitre.first().map(|m| m.tactic.clone().to_lowercase().replace(' ', "-")).unwrap_or_else(|| "general".into()),
            subcategory: None,
            mitre,
            severity: severity.into(),
            risk: SentinelRisk {
                base_score,
                confidence: 0.8,
                multipliers: vec![],
            },
            condition: full_condition,
            and_conditions: vec![],
            or_conditions: vec![],
            not_conditions: vec![],
            actions: vec![],
            suppressions: vec![],
            tests: vec![],
        },
    }
}

pub fn import_sigma_file(path: &str) -> anyhow::Result<SentinelRule> {
    let content = std::fs::read_to_string(path)?;
    let sigma: SigmaRule = serde_yaml::from_str(&content)?;
    Ok(convert_sigma_to_sentinel(&sigma))
}

pub fn import_sigma_dir(dir: &str) -> anyhow::Result<Vec<SentinelRule>> {
    let mut rules = Vec::new();
    let entries = std::fs::read_dir(dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "yml" || e == "yaml").unwrap_or(false) {
            match import_sigma_file(&path.to_string_lossy()) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    eprintln!("Failed to import {}: {e}", path.display());
                }
            }
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sigma_rule() {
        let yaml = r#"
title: Test Rule
id: test-001
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: high
"#;
        let sigma: SigmaRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(sigma.title, "Test Rule");
        assert_eq!(sigma.level, Some("high".into()));

        let sentinel = convert_sigma_to_sentinel(&sigma);
        assert!(sentinel.rule.condition.contains("sentinel.process.create"));
        assert!(sentinel.rule.condition.contains("powershell"));
        assert_eq!(sentinel.rule.severity, "Error");
    }

    #[test]
    fn test_parse_with_mitre_tags() {
        let yaml = r#"
title: WMI Execution
id: test-002
status: stable
logsource:
  category: process_creation
detection:
  selection:
    Image|contains: 'wmic'
  condition: selection
tags:
  - attack.t1047
  - attack.execution
level: medium
"#;
        let sigma: SigmaRule = serde_yaml::from_str(yaml).unwrap();
        let sentinel = convert_sigma_to_sentinel(&sigma);
        assert!(!sentinel.rule.mitre.is_empty());
        assert_eq!(sentinel.rule.risk.base_score, 55);
    }

    #[test]
    fn test_network_rule_mapping() {
        let yaml = r#"
title: Suspicious Network
id: test-003
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort: 4444
  condition: selection
level: critical
"#;
        let sigma: SigmaRule = serde_yaml::from_str(yaml).unwrap();
        let sentinel = convert_sigma_to_sentinel(&sigma);
        assert!(sentinel.rule.condition.contains("sentinel.network.connect"));
        assert_eq!(sentinel.rule.severity, "Critical");
    }
}
