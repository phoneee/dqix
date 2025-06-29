use crate::{AssessmentResult, ProbeResult};
use anyhow::Result;
use colored::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ProbeLevel {
    Critical = 1,
    Important = 2,
    Informational = 3,
}

fn get_probe_level(probe_id: &str) -> ProbeLevel {
    let normalized = probe_id.to_lowercase().replace(" ", "_");
    match normalized.as_str() {
        "tls" | "tls_security" | "security_headers" => ProbeLevel::Critical,
        "https" | "https_access" | "dns" | "dns_security" => ProbeLevel::Important,
        _ => ProbeLevel::Informational,
    }
}

fn get_probe_icon(probe_id: &str) -> &'static str {
    let normalized = probe_id.to_lowercase().replace(" ", "_");
    match normalized.as_str() {
        "tls" | "tls_security" => "🔐",
        "dns" | "dns_security" => "🌍",
        "https" | "https_access" => "🌐",
        "security_headers" => "🛡️",
        _ => "🔍",
    }
}

fn get_probe_display_name(probe_id: &str) -> String {
    match probe_id.to_lowercase().as_str() {
        "tls" => "TLS/SSL Security".to_string(),
        "dns" => "DNS Security".to_string(),
        "https" => "HTTPS Configuration".to_string(),
        "security_headers" => "Security Headers".to_string(),
        _ => probe_id.to_string(),
    }
}

fn display_probe_result(probe: &ProbeResult) {
    let icon = get_probe_icon(&probe.probe_id);
    let display_name = get_probe_display_name(&probe.probe_id);
    
    // Color and status based on score
    let (status, color) = match probe.score {
        s if s >= 0.8 => ("✅ EXCELLENT", "green"),
        s if s >= 0.6 => ("⚠️  GOOD", "yellow"),
        s if s >= 0.4 => ("🔶 FAIR", "yellow"),
        _ => ("❌ POOR", "red"),
    };
    
    // Score bar
    let bar_length = 20;
    let filled = (probe.score * bar_length as f64) as usize;
    let empty = bar_length - filled;
    let bar = "█".repeat(filled) + &"░".repeat(empty);
    
    // Print probe result
    print!("  {} {:<20} ", icon, display_name);
    
    match color {
        "green" => print!("{:>3.0}% ", (probe.score * 100.0).to_string().green()),
        "yellow" => print!("{:>3.0}% ", (probe.score * 100.0).to_string().yellow()),
        _ => print!("{:>3.0}% ", (probe.score * 100.0).to_string().red()),
    }
    
    print!("[");
    match color {
        "green" => print!("{}", bar.green()),
        "yellow" => print!("{}", bar.yellow()),
        _ => print!("{}", bar.red()),
    }
    print!("] ");
    
    match color {
        "green" => println!("{}", status.green()),
        "yellow" => println!("{}", status.yellow()),
        _ => println!("{}", status.red()),
    }
    
    // Show key details
    if let Some(exec_time) = probe.details.execution_time {
        println!("     • Execution Time: {:.2}s", exec_time);
    }
    if let Some(protocol) = &probe.details.protocol_version {
        println!("     • Protocol: {}", protocol);
    }
    if let Some(cert) = &probe.details.certificate_valid {
        println!("     • Certificate: {}", cert);
    }
    if let Some(dnssec) = &probe.details.dnssec_enabled {
        println!("     • DNSSEC: {}", dnssec);
    }
}

pub fn output(result: &AssessmentResult) -> Result<()> {
    println!("\n{}", "🔍 DQIX Internet Observability Platform".bold().blue());
    println!("Analyzing: {}", result.domain.bold());
    println!();
    
    // Overall score bar
    let overall_bar_length = 40;
    let overall_filled = (result.overall_score * overall_bar_length as f64) as usize;
    let overall_empty = overall_bar_length - overall_filled;
    let overall_bar = "█".repeat(overall_filled) + &"░".repeat(overall_empty);
    
    println!("{}: {:.0}% {}", 
             "Overall Score".bold(), 
             result.overall_score * 100.0,
             result.compliance_level.bold().green()
    );
    println!("[{}{}]", overall_bar.green(), "░".repeat(overall_empty));
    println!();
    
    // Group probes by level
    let mut critical_probes = Vec::new();
    let mut important_probes = Vec::new();
    let mut informational_probes = Vec::new();
    
    for probe in &result.probe_results {
        match get_probe_level(&probe.probe_id) {
            ProbeLevel::Critical => critical_probes.push(probe),
            ProbeLevel::Important => important_probes.push(probe),
            ProbeLevel::Informational => informational_probes.push(probe),
        }
    }
    
    // Sort within each level by score (ascending to show worst first)
    critical_probes.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
    important_probes.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
    informational_probes.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
    
    println!("{}", "Security Assessment (3-Level Hierarchy):".bold());
    println!();
    
    // Display Level 1: Critical Security
    if !critical_probes.is_empty() {
        println!("{}", "🚨 CRITICAL SECURITY".bold().red());
        println!("{}", "━".repeat(60));
        for probe in critical_probes {
            display_probe_result(probe);
        }
        println!();
    }
    
    // Display Level 2: Important Configuration
    if !important_probes.is_empty() {
        println!("{}", "⚠️  IMPORTANT CONFIGURATION".bold().yellow());
        println!("{}", "━".repeat(60));
        for probe in important_probes {
            display_probe_result(probe);
        }
        println!();
    }
    
    // Display Level 3: Best Practices
    if !informational_probes.is_empty() {
        println!("{}", "ℹ️  BEST PRACTICES".bold().blue());
        println!("{}", "━".repeat(60));
        for probe in informational_probes {
            display_probe_result(probe);
        }
        println!();
    }
    
    println!("\n{}", "📋 METADATA".bold().blue());
    println!("{}", "-".repeat(30).blue());
    println!("Engine: {}", result.metadata.engine);
    println!("Version: {}", result.metadata.version);
    println!("Probes: {}", result.metadata.probe_count);
    println!("Timeout Policy: {}", result.metadata.timeout_policy);
    println!("Scoring Method: {}", result.metadata.scoring_method);
    
    Ok(())
} 