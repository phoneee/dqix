use crate::AssessmentResult;
use anyhow::Result;

pub fn output(result: &AssessmentResult) -> Result<()> {
    println!("domain,overall_score,compliance_level,timestamp");
    println!("{},{},{},{}", 
             result.domain, 
             result.overall_score, 
             result.compliance_level, 
             result.timestamp);
    
    for probe in &result.probe_results {
        println!("{},{},{},{},{}", 
                 result.domain,
                 probe.probe_id,
                 probe.score,
                 probe.category,
                 probe.timestamp);
    }
    
    Ok(())
} 