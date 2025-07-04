use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::dsl::DslParser;
use crate::probes::{Probe, ProbeResult};
use colored::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct AssessmentResult {
    pub domain: String,
    pub score: f64,
    pub level: String,
    pub timestamp: DateTime<Utc>,
    pub probe_results: HashMap<String, ProbeResult>,
    pub duration: Duration,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug)]
pub struct Config {
    pub dsl_path: String,
    pub timeout: Duration,
    pub concurrent: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dsl_path: "../../dsl/enhanced_probe_definition.yaml".to_string(),
            timeout: Duration::from_secs(30),
            concurrent: 4,
        }
    }
}

pub struct Assessor {
    config: Config,
    probes: Vec<Box<dyn Probe>>,
}

impl Assessor {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            probes: Vec::new(),
        }
    }

    pub async fn load_config(&mut self, _path: &str) -> Result<()> {
        // Load DSL configuration
        let mut dsl_parser = DslParser::new();
        dsl_parser.load_from_file(&self.config.dsl_path)?;
        
        // Initialize probes from DSL
        self.probes.clear();
        if let Some(definition) = dsl_parser.definition() {
            for (probe_name, _) in &definition.probes {
                let probe_config = crate::probes::ProbeConfig {
                    probe_type: probe_name.clone(),
                    enabled: true,
                    timeout: Some(30),
                };
                let probe = crate::probes::create_probe(&probe_config)?;
                self.probes.push(probe);
            }
        }
        
        Ok(())
    }

    pub async fn assess(&mut self, domain: &str) -> Result<AssessmentResult> {
        let start_time = Instant::now();
        let timestamp = Utc::now();
        
        println!("{}", format!("📊 Assessing domain: {}", domain).blue());
        
        // Initialize default probes if not loaded from config
        if self.probes.is_empty() {
            self.initialize_default_probes();
        }

        // Create progress bar
        let pb = indicatif::ProgressBar::new(self.probes.len() as u64);
        pb.set_style(indicatif::ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}"
        )?);
        pb.set_message("Running probes...");

        // Run probes sequentially for now (to avoid lifetime issues)
        let mut probe_results = HashMap::new();
        let domain = domain.to_string();
        
        for probe in &self.probes {
            let probe_name = probe.name();
            
            match probe.execute(&domain).await {
                Ok(result) => {
                    probe_results.insert(probe_name.clone(), result);
                }
                Err(e) => {
                    probe_results.insert(probe_name.clone(), ProbeResult {
                        name: probe_name.clone(),
                        category: "error".to_string(),
                        score: 0.0,
                        status: "error".to_string(),
                        message: format!("Error: {}", e),
                        error: Some(e.to_string()),
                        details: HashMap::new(),
                        duration: Duration::from_secs(0),
                        timestamp,
                    });
                }
            }
            pb.inc(1);
        }

        pb.finish_with_message("Assessment completed!");

        // Calculate overall score
        let overall_score = self.calculate_overall_score(&probe_results);
        let level = self.calculate_level(overall_score);

        let mut metadata = HashMap::new();
        metadata.insert("implementation".to_string(), serde_json::Value::String("rust".to_string()));
        metadata.insert("version".to_string(), serde_json::Value::String("1.2.0".to_string()));
        metadata.insert("probes_count".to_string(), serde_json::Value::Number(serde_json::Number::from(self.probes.len())));

        Ok(AssessmentResult {
            domain: domain.to_string(),
            score: overall_score,
            level,
            timestamp,
            probe_results,
            duration: start_time.elapsed(),
            metadata,
        })
    }

    fn initialize_default_probes(&mut self) {
        self.probes.push(Box::new(crate::probes::TlsProbe::new()));
        self.probes.push(Box::new(crate::probes::DnsProbe::new()));
        self.probes.push(Box::new(crate::probes::HttpsProbe::new()));
        self.probes.push(Box::new(crate::probes::SecurityHeadersProbe::new()));
    }

    fn calculate_overall_score(&self, results: &HashMap<String, ProbeResult>) -> f64 {
        if results.is_empty() {
            return 0.0;
        }

        let total_score: f64 = results.values().map(|r| r.score).sum();
        let total_weight = results.len() as f64; // Default equal weighting

        total_score / total_weight
    }

    fn calculate_level(&self, score: f64) -> String {
        match score {
            s if s >= 0.95 => "A+".to_string(),
            s if s >= 0.85 => "A".to_string(),
            s if s >= 0.75 => "B".to_string(),
            s if s >= 0.65 => "C".to_string(),
            s if s >= 0.55 => "D".to_string(),
            s if s >= 0.45 => "E".to_string(),
            _ => "F".to_string(),
        }
    }
} 