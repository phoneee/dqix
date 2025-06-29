use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Complete probe definition from DSL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeDefinition {
    pub version: String,
    pub metadata: Metadata,
    pub config: Config,
    pub weights: Weights,
    pub probes: HashMap<String, Probe>,
    pub output: Output,
    pub compliance_levels: HashMap<String, f64>,
    pub error_handling: HashMap<String, String>,
    pub i18n: I18n,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub description: String,
    pub authors: Vec<String>,
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Weights {
    pub tls: f64,
    pub dns: f64,
    pub security_headers: f64,
    pub https: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub name: String,
    pub category: String,
    pub priority: u32,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    #[serde(rename = "type")]
    pub check_type: String,
    pub target: Option<String>,
    pub header: Option<String>,
    pub port: Option<u16>,
    pub criteria: HashMap<String, serde_yaml::Value>,
    pub scoring: HashMap<String, i32>,
    pub sub_checks: Option<HashMap<String, SubCheck>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubCheck {
    pub query: String,
    pub pattern: Option<String>,
    pub domain_prefix: Option<String>,
    pub scoring: HashMap<String, i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Output {
    pub formats: Vec<String>,
    pub fields: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct I18n {
    pub default_language: String,
    pub supported_languages: Vec<String>,
}

/// DSL Parser for DQIX probe definitions
pub struct DslParser {
    definition: Option<ProbeDefinition>,
}

impl DslParser {
    /// Create a new DSL parser
    pub fn new() -> Self {
        Self { definition: None }
    }

    /// Load and parse DSL from file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read DSL file: {:?}", path.as_ref()))?;

        self.load_from_string(&content)
    }

    /// Load and parse DSL from string
    pub fn load_from_string(&mut self, content: &str) -> Result<()> {
        let definition: ProbeDefinition = serde_yaml::from_str(content)
            .context("Failed to parse DSL YAML")?;

        self.validate(&definition)?;
        self.definition = Some(definition);

        Ok(())
    }

    /// Get the parsed probe definition
    pub fn definition(&self) -> Option<&ProbeDefinition> {
        self.definition.as_ref()
    }

    /// Get a specific probe by name
    pub fn get_probe(&self, name: &str) -> Result<&Probe> {
        let definition = self.definition.as_ref()
            .context("No DSL definition loaded")?;

        definition.probes.get(name)
            .with_context(|| format!("Probe '{}' not found", name))
    }

    /// Get all probe names
    pub fn get_all_probe_names(&self) -> Vec<String> {
        self.definition.as_ref()
            .map(|def| def.probes.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Get weight for a specific probe
    pub fn get_weight(&self, probe_name: &str) -> f64 {
        let Some(definition) = &self.definition else {
            return 0.0;
        };

        match probe_name {
            "tls" => definition.weights.tls,
            "dns" => definition.weights.dns,
            "security_headers" => definition.weights.security_headers,
            "https" => definition.weights.https,
            _ => 0.0,
        }
    }

    /// Get compliance level for a given score
    pub fn get_compliance_level(&self, score: f64) -> String {
        let Some(definition) = &self.definition else {
            return "unknown".to_string();
        };

        if score >= *definition.compliance_levels.get("advanced").unwrap_or(&0.85) {
            "advanced".to_string()
        } else if score >= *definition.compliance_levels.get("standard").unwrap_or(&0.70) {
            "standard".to_string()
        } else if score >= *definition.compliance_levels.get("basic").unwrap_or(&0.50) {
            "basic".to_string()
        } else {
            "needs_improvement".to_string()
        }
    }

    /// Get configuration
    pub fn get_config(&self) -> Option<&Config> {
        self.definition.as_ref().map(|def| &def.config)
    }

    /// Validate the DSL definition
    fn validate(&self, definition: &ProbeDefinition) -> Result<()> {
        // Check version
        if definition.version.is_empty() {
            anyhow::bail!("Version is required");
        }

        // Check weights sum to 1.0 (with tolerance)
        let total_weight = definition.weights.tls 
            + definition.weights.dns 
            + definition.weights.security_headers 
            + definition.weights.https;

        if (total_weight - 1.0).abs() > 0.01 {
            anyhow::bail!("Weights must sum to 1.0, got {:.2}", total_weight);
        }

        // Check required probes exist
        let required_probes = ["tls", "dns", "security_headers", "https"];
        for required in &required_probes {
            if !definition.probes.contains_key(*required) {
                anyhow::bail!("Required probe '{}' is missing", required);
            }
        }

        Ok(())
    }
}

impl Default for DslParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsl_parser_creation() {
        let parser = DslParser::new();
        assert!(parser.definition().is_none());
    }

    #[test]
    fn test_empty_probe_names() {
        let parser = DslParser::new();
        assert!(parser.get_all_probe_names().is_empty());
    }

    #[test]
    fn test_weight_without_definition() {
        let parser = DslParser::new();
        assert_eq!(parser.get_weight("tls"), 0.0);
    }

    #[test]
    fn test_compliance_level_without_definition() {
        let parser = DslParser::new();
        assert_eq!(parser.get_compliance_level(0.9), "unknown");
    }
} 