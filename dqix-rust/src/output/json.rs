use crate::AssessmentResult;
use anyhow::Result;

pub fn output(result: &AssessmentResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{}", json);
    Ok(())
} 