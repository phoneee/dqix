use crate::AssessmentResult;
use anyhow::Result;
use colored::*;

pub fn output(result: &AssessmentResult) -> Result<()> {
    println!("\n{}", "📊 DOMAIN QUALITY ASSESSMENT REPORT".bold().cyan());
    println!("{}", "=".repeat(60).cyan());
    
    println!("\n🌐 Domain: {}", result.domain.bold());
    println!("📈 Overall Score: {:.1}%", (result.overall_score * 100.0));
    println!("🏆 Compliance Level: {}", result.compliance_level.bold().green());
    println!("⏱️  Execution Time: {:.2}s", result.execution_time);
    
    println!("\n{}", "🔍 DETAILED PROBE RESULTS".bold().yellow());
    println!("{}", "-".repeat(50).yellow());
    
    for probe in &result.probe_results {
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
            println!("  Execution Time: {:.2}s", exec_time);
        }
        
        // Show key details
        if let Some(protocol) = &probe.details.protocol_version {
            println!("  Protocol: {}", protocol);
        }
        if let Some(cert) = &probe.details.certificate_valid {
            println!("  Certificate: {}", cert);
        }
        if let Some(dnssec) = &probe.details.dnssec_enabled {
            println!("  DNSSEC: {}", dnssec);
        }
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