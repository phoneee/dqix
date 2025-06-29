use ahash::HashMap;
use clap::Parser;
use colored::*;
use dashmap::DashMap;
use eyre::{eyre, Result as EyreResult, WrapErr};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

mod cli;
mod config;
mod core;
mod dsl;
mod probes;
mod output;

use cli::Commands;
use core::Assessor;

type DqixResult<T> = EyreResult<T>;
type FastHashMap<K, V> = HashMap<K, V>;
type SharedState<T> = Arc<RwLock<T>>;

// Modern Rust type aliases for better performance
type SmallString = SmallVec<[u8; 32]>;
type ProbeCache = Arc<DashMap<String, ProbeResult>>;

// Global probe cache using modern patterns
static PROBE_CACHE: Lazy<ProbeCache> = Lazy::new(|| Arc::new(DashMap::new()));

// Immutable Domain Types
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Domain {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProbeDetails {
    pub protocol_version: Option<Arc<str>>,
    pub cipher_suite: Option<Arc<str>>,
    pub certificate_valid: Option<Arc<str>>,
    pub cert_chain_length: Option<Arc<str>>,
    pub key_exchange: Option<Arc<str>>,
    pub pfs_support: Option<Arc<str>>,
    pub https_accessible: Option<Arc<str>>,
    pub http_redirects: Option<Arc<str>>,
    pub hsts_header: Option<Arc<str>>,
    pub hsts_max_age: Option<Arc<str>>,
    pub http2_support: Option<Arc<str>>,
    pub dnssec_enabled: Option<Arc<str>>,
    pub spf_record: Option<Arc<str>>,
    pub dmarc_policy: Option<Arc<str>>,
    pub caa_records: Option<Arc<str>>,
    pub csp: Option<Arc<str>>,
    pub x_frame_options: Option<Arc<str>>,
    pub x_content_type_options: Option<Arc<str>>,
    pub referrer_policy: Option<Arc<str>>,
    pub server_header: Option<Arc<str>>,
    pub response_time: Option<Arc<str>>,
    pub execution_time: Option<f64>,
    pub custom_fields: FastHashMap<Arc<str>, Arc<str>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProbeResult {
    pub probe_id: String,
    pub score: f64,
    pub category: String,
    pub details: ProbeDetails,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Metadata {
    pub engine: String,
    pub version: String,
    pub probe_count: usize,
    pub timeout_policy: String,
    pub scoring_method: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AssessmentResult {
    pub domain: String,
    pub overall_score: f64,
    pub compliance_level: String,
    pub probe_results: Vec<ProbeResult>,
    pub timestamp: u64,
    pub execution_time: f64,
    pub metadata: Metadata,
}

#[derive(Parser)]
#[command(name = "dqix")]
#[command(about = "Domain Quality Index - Rust Implementation")]
#[command(version = "1.2.0")]
#[command(long_about = "DQIX (Domain Quality Index) is a multi-language tool for measuring domain security, performance, and compliance.\n\nThis is the Rust implementation, designed for memory safety and blazing fast performance.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Domain to assess (if no subcommand is provided)
    domain: Option<String>,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// Output format (json, csv, report)
    #[arg(short, long, default_value = "json")]
    output: String,
    
    /// Configuration file path
    #[arg(short, long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Some(command) => {
            cli::handle_command(command).await?;
        }
        None => {
            if let Some(domain) = cli.domain {
                assess_domain(domain, cli.output, cli.config).await?;
            } else {
                eprintln!("{}", "Error: Please provide a domain to assess or use a subcommand".red());
                std::process::exit(1);
            }
        }
    }
    
    Ok(())
}

async fn assess_domain(domain: String, output_format: String, config_file: Option<String>) -> anyhow::Result<()> {
    println!("{}", "🔍 DQIX - Domain Quality Assessment (Rust)".cyan());
    println!("{}", "=".repeat(50).cyan());
    
    let start = Instant::now();
    
    let mut assessor = Assessor::new();
    
    if let Some(config_path) = config_file {
        assessor.load_config(&config_path).await?;
    }
    
    let core_result = assessor.assess(&domain).await?;
    
    // Convert core::AssessmentResult to our main AssessmentResult
    // Convert HashMap probe results to Vec
    let probe_count = core_result.probe_results.len();
    let probe_results: Vec<ProbeResult> = core_result.probe_results
        .into_iter()
        .map(|(probe_id, result)| ProbeResult {
            probe_id,
            score: result.score,
            category: result.category,
            details: ProbeDetails {
                protocol_version: result.details.get("protocol_version").and_then(|v| v.as_str()).map(String::from),
                cipher_suite: result.details.get("cipher_suite").and_then(|v| v.as_str()).map(String::from),
                certificate_valid: result.details.get("certificate_valid").and_then(|v| v.as_str()).map(String::from),
                cert_chain_length: result.details.get("cert_chain_length").and_then(|v| v.as_str()).map(String::from),
                key_exchange: result.details.get("key_exchange").and_then(|v| v.as_str()).map(String::from),
                pfs_support: result.details.get("pfs_support").and_then(|v| v.as_str()).map(String::from),
                https_accessible: result.details.get("https_accessible").and_then(|v| v.as_str()).map(String::from),
                http_redirects: result.details.get("http_redirects").and_then(|v| v.as_str()).map(String::from),
                hsts_header: result.details.get("hsts_header").and_then(|v| v.as_str()).map(String::from),
                hsts_max_age: result.details.get("hsts_max_age").and_then(|v| v.as_str()).map(String::from),
                http2_support: result.details.get("http2_support").and_then(|v| v.as_str()).map(String::from),
                dnssec_enabled: result.details.get("dnssec_enabled").and_then(|v| v.as_str()).map(String::from),
                spf_record: result.details.get("spf_record").and_then(|v| v.as_str()).map(String::from),
                dmarc_policy: result.details.get("dmarc_policy").and_then(|v| v.as_str()).map(String::from),
                caa_records: result.details.get("caa_records").and_then(|v| v.as_str()).map(String::from),
                csp: result.details.get("csp").and_then(|v| v.as_str()).map(String::from),
                x_frame_options: result.details.get("x_frame_options").and_then(|v| v.as_str()).map(String::from),
                x_content_type_options: result.details.get("x_content_type_options").and_then(|v| v.as_str()).map(String::from),
                referrer_policy: result.details.get("referrer_policy").and_then(|v| v.as_str()).map(String::from),
                server_header: result.details.get("server_header").and_then(|v| v.as_str()).map(String::from),
                response_time: result.details.get("response_time").and_then(|v| v.as_str()).map(String::from),
                execution_time: Some(result.duration.as_secs_f64()),
                custom_fields: HashMap::new(),
            },
            timestamp: result.timestamp.timestamp() as u64,
        })
        .collect();
    
    let result = AssessmentResult {
        domain: core_result.domain,
        overall_score: core_result.score,
        compliance_level: core_result.level,
        probe_results,
        timestamp: core_result.timestamp.timestamp() as u64,
        execution_time: core_result.duration.as_secs_f64(),
        metadata: Metadata {
            engine: "Rust DQIX v1.2.0".to_string(),
            version: "1.2.0".to_string(),
            probe_count,
            timeout_policy: "30s per probe".to_string(),
            scoring_method: "Weighted composite".to_string(),
        },
    };
    
    println!("{}", format!("Assessment completed in {:?}", start.elapsed()).green());
    
    // Output results
    match output_format.as_str() {
        "csv" => output::csv::output(&result)?,
        "report" => output::report::output(&result)?,
        _ => output::json::output(&result)?,
    }
    
    Ok(())
}

// Pure Functions for Domain Logic
fn validate_domain(domain_name: &str) -> DqixResult<Domain> {
    // Modern Rust let chain pattern for cleaner conditional logic
    if let Some(validation_error) = [
        (domain_name.is_empty(), "Domain name cannot be empty"),
        (!domain_name.contains('.'), "Domain name must contain at least one dot"),
        (domain_name.len() > 253, "Domain name too long"),
        (domain_name.contains(' '), "Domain name cannot contain spaces"),
        (domain_name == "localhost", "localhost not allowed"),
    ]
    .iter()
    .find_map(|(condition, error)| condition.then_some(*error))
    {
        return Err(eyre!(validation_error));
    }

    Ok(Domain {
        name: domain_name.to_string(),
    })
}

fn calculate_probe_score(probe_data: &HashMap<String, String>) -> DqixResult<f64> {
    let probe_type = probe_data
        .get("probe_type")
        .ok_or("Missing probe_type")?;

    match probe_type.as_str() {
        "tls" => calculate_tls_score(probe_data),
        "dns" => calculate_dns_score(probe_data),
        "https" => calculate_https_score(probe_data),
        "security_headers" => calculate_security_headers_score(probe_data),
        _ => Err(format!("Unknown probe type: {}", probe_type)),
    }
}

fn calculate_tls_score(probe_data: &FastHashMap<String, String>) -> DqixResult<f64> {
    let mut score: f32 = 0.0;

    // Modern Rust pattern matching with let chains
    if let Some(protocol) = probe_data.get("protocol_version") {
        score += match protocol.as_str() {
            p if p.contains("1.3") => 0.4,
            p if p.contains("1.2") => 0.3,
            p if p.contains("1.1") => 0.2,
            _ => 0.0,
        };
    }

    // Using HashMap::extract_if pattern (simulated)
    let scoring_rules = [
        ("certificate_valid", "true", 0.3),
        ("cipher_strength", "strong", 0.3),
        ("cipher_strength", "medium", 0.2),
    ];

    score += scoring_rules
        .iter()
        .filter_map(|(key, expected, points)| {
            probe_data
                .get(*key)
                .filter(|value| value.as_str() == *expected)
                .map(|_| points)
        })
        .sum::<f32>();

    Ok(score.min(1.0) as f64)
}

fn calculate_dns_score(probe_data: &FastHashMap<String, String>) -> DqixResult<f64> {
    // Modern functional approach with iterator chaining
    let score = [
        ("dnssec_enabled", "true", 0.4),
        ("spf_record", "present", 0.3),
        ("dmarc_policy", "present", 0.3),
    ]
    .iter()
    .map(|(key, expected, points)| {
        probe_data
            .get(*key)
            .filter(|value| value.as_str() == *expected)
            .map_or(0.0, |_| *points)
    })
    .sum::<f32>();

    Ok(score.min(1.0) as f64)
}

fn calculate_https_score(probe_data: &FastHashMap<String, String>) -> DqixResult<f64> {
    // Using modern slice chunking methods
    let https_checks = [("https_accessible", "true", 0.5), ("hsts_header", "present", 0.5)];
    
    let score = https_checks
        .iter()
        .filter_map(|(key, expected, points)| {
            probe_data
                .get(*key)
                .filter(|value| value.as_str() == *expected)
                .map(|_| points)
        })
        .sum::<f32>();

    Ok(score.min(1.0) as f64)
}

fn calculate_security_headers_score(probe_data: &FastHashMap<String, String>) -> DqixResult<f64> {
    // Modern parallel processing with rayon
    let headers = ["hsts", "csp", "x_frame_options", "x_content_type_options"];
    
    let score = headers
        .par_iter()
        .map(|header| {
            probe_data
                .get(*header)
                .filter(|value| matches!(value.as_str(), "present" | "true"))
                .map_or(0.0, |_| 0.25)
        })
        .sum::<f32>();

    Ok(score.min(1.0) as f64)
}

fn calculate_overall_score(probe_results: &[ProbeResult]) -> DqixResult<f64> {
    if probe_results.is_empty() {
        return Err("No probe results to calculate score from".to_string());
    }

    let weights = [
        ("tls", 0.35),
        ("dns", 0.25),
        ("https", 0.20),
        ("security_headers", 0.20),
    ];

    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;

    for (probe_type, weight) in &weights {
        if let Some(result) = probe_results.iter().find(|r| r.probe_id == *probe_type) {
            weighted_sum += result.score * weight;
        total_weight += weight;
    }
    }

    if total_weight > 0.0 {
        Ok(weighted_sum / total_weight)
    } else {
        Ok(0.0)
}
    }

fn determine_compliance_level(score: f64) -> DqixResult<String> {
    let level = if score >= 0.90 {
        "Excellent"
    } else if score >= 0.80 {
        "Advanced"
    } else if score >= 0.60 {
        "Standard"
    } else if score >= 0.40 {
        "Basic"
    } else {
        "Poor"
    };

    Ok(level.to_string())
}

fn compose_assessment(
    domain: Domain,
    probe_results: Vec<ProbeResult>,
    timestamp: f64,
) -> DqixResult<AssessmentResult> {
    let overall_score = calculate_overall_score(&probe_results)?;
    let compliance_level = determine_compliance_level(overall_score)?;
    let probe_count = probe_results.len();

    Ok(AssessmentResult {
        domain: domain.name,
        overall_score,
        compliance_level,
        probe_results,
        timestamp: timestamp as u64,
        execution_time: 0.5,
        metadata: Metadata {
            engine: "Rust DQIX v1.2.0".to_string(),
            version: "1.2.0".to_string(),
            probe_count,
            timeout_policy: "30s per probe".to_string(),
            scoring_method: "Weighted composite".to_string(),
        },
    })
}

fn pipe<T, U, V>(f: impl Fn(T) -> U, g: impl Fn(U) -> V) -> impl Fn(T) -> V {
    move |x| g(f(x))
}

fn map<T, U>(f: impl Fn(&T) -> U) -> impl Fn(Vec<T>) -> Vec<U> {
    move |vec| vec.iter().map(&f).collect()
}

fn filter<T>(predicate: impl Fn(&T) -> bool) -> impl Fn(Vec<T>) -> Vec<T> {
    move |vec| vec.into_iter().filter(&predicate).collect()
}

fn reduce<T, U: Clone>(f: impl Fn(U, &T) -> U, initial: U) -> impl Fn(Vec<T>) -> U {
    move |vec| vec.iter().fold(initial.clone(), &f)
}

// Mock data generation functions
fn generate_mock_probe_results(_domain: &Domain) -> Vec<ProbeResult> {
    let timestamp = get_current_timestamp();

    vec![
        ProbeResult {
            probe_id: "tls".to_string(),
            score: 0.923,
            category: "security".to_string(),
            timestamp,
            details: ProbeDetails {
                protocol_version: Some("TLS 1.3".to_string()),
                cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
                certificate_valid: Some("true".to_string()),
                cert_chain_length: Some("3".to_string()),
                key_exchange: Some("ECDHE".to_string()),
                pfs_support: Some("true".to_string()),
                execution_time: Some(0.45),
                custom_fields: [
                    ("vulnerability_scan".to_string(), "clean".to_string()),
                    ("ocsp_stapling".to_string(), "enabled".to_string()),
                    ("ct_logs".to_string(), "present".to_string()),
                ].iter().cloned().collect(),
                ..Default::default()
            },
        },
        ProbeResult {
            probe_id: "https".to_string(),
            score: 0.891,
            category: "protocol".to_string(),
            timestamp,
            details: ProbeDetails {
                https_accessible: Some("true".to_string()),
                http_redirects: Some("301".to_string()),
                hsts_header: Some("max-age=31536000; includeSubDomains".to_string()),
                hsts_max_age: Some("31536000".to_string()),
                http2_support: Some("true".to_string()),
                execution_time: Some(0.32),
                custom_fields: [
                    ("hsts_subdomains".to_string(), "true".to_string()),
                    ("http3_support".to_string(), "false".to_string()),
                    ("compression_type".to_string(), "gzip".to_string()),
                ].iter().cloned().collect(),
                    ..Default::default()
                },
            },
            ProbeResult {
                probe_id: "dns".to_string(),
            score: 0.856,
                category: "infrastructure".to_string(),
            timestamp,
                details: ProbeDetails {
                    dnssec_enabled: Some("true".to_string()),
                    spf_record: Some("v=spf1 include:_spf.google.com ~all".to_string()),
                dmarc_policy: Some("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com".to_string()),
                    caa_records: Some("0 issue \"letsencrypt.org\"".to_string()),
                execution_time: Some(0.89),
                custom_fields: [
                    ("ipv4_records".to_string(), "present".to_string()),
                    ("ipv6_records".to_string(), "present".to_string()),
                    ("dnssec_chain_valid".to_string(), "true".to_string()),
                    ("dkim_selectors".to_string(), "google, mailchimp".to_string()),
                    ("mx_records".to_string(), "present".to_string()),
                    ("ns_records".to_string(), "cloudflare".to_string()),
                    ("ttl_analysis".to_string(), "optimized".to_string()),
                ].iter().cloned().collect(),
                    ..Default::default()
                },
            },
            ProbeResult {
            probe_id: "security_headers".to_string(),
            score: 0.734,
                category: "security".to_string(),
            timestamp,
                details: ProbeDetails {
                csp: Some("default-src 'self'; script-src 'self' 'unsafe-inline'".to_string()),
                x_frame_options: Some("SAMEORIGIN".to_string()),
                x_content_type_options: Some("nosniff".to_string()),
                referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
                server_header: Some("hidden".to_string()),
                execution_time: Some(0.56),
                custom_fields: [
                    ("hsts".to_string(), "max-age=31536000; includeSubDomains".to_string()),
                    ("permissions_policy".to_string(), "camera=(), microphone=()".to_string()),
                    ("x_xss_protection".to_string(), "1; mode=block".to_string()),
                    ("content_type".to_string(), "text/html; charset=utf-8".to_string()),
                    ("powered_by".to_string(), "hidden".to_string()),
                ].iter().cloned().collect(),
                    ..Default::default()
                },
            },
    ]
}

fn display_assessment_results(assessment: &AssessmentResult) {
    println!("\n{}", "📊 DOMAIN QUALITY ASSESSMENT RESULTS".bold().cyan());
    println!("{}", "=".repeat(60).cyan());
    
    println!("\n🌐 Domain: {}", assessment.domain.bold());
    println!("📈 Overall Score: {:.1}%", (assessment.overall_score * 100.0));
    println!("🏆 Compliance Level: {}", assessment.compliance_level.bold().green());
    println!("⏱️  Execution Time: {:.2}s", assessment.execution_time);
    
    println!("\n{}", "🔍 PROBE RESULTS".bold().yellow());
    println!("{}", "-".repeat(40).yellow());
    
    for probe in &assessment.probe_results {
        let score_color = match probe.score {
            s if s >= 0.9 => "green",
            s if s >= 0.7 => "yellow", 
            _ => "red"
        };
        
        println!("\n• {} ({})", probe.probe_id.bold(), probe.category);
        println!("  Score: {:.1}% {}", 
                (probe.score * 100.0), 
                match score_color {
                    "green" => "✅".green(),
                    "yellow" => "⚠️".yellow(),
                    _ => "❌".red()
                }
        );
        
        if let Some(exec_time) = probe.details.execution_time {
            println!("  Time: {:.2}s", exec_time);
        }
    }
    }
    
fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Default for ProbeDetails {
    fn default() -> Self {
        Self {
            protocol_version: None,
            cipher_suite: None,
            certificate_valid: None,
            cert_chain_length: None,
            key_exchange: None,
            pfs_support: None,
            https_accessible: None,
            http_redirects: None,
            hsts_header: None,
            hsts_max_age: None,
            http2_support: None,
            dnssec_enabled: None,
            spf_record: None,
            dmarc_policy: None,
            caa_records: None,
            csp: None,
            x_frame_options: None,
            x_content_type_options: None,
            referrer_policy: None,
            server_header: None,
            response_time: None,
            execution_time: None,
            custom_fields: HashMap::new(),
        }
    }
} 