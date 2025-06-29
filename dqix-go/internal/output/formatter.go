package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dqix-org/dqix/internal/core"
	"github.com/fatih/color"
)

type Formatter interface {
	Output(result *core.AssessmentResult) error
}

type JSONFormatter struct{}
type CSVFormatter struct{}
type ReportFormatter struct{}

func NewFormatter(format string) Formatter {
	switch strings.ToLower(format) {
	case "csv":
		return &CSVFormatter{}
	case "report":
		return &ReportFormatter{}
	default:
		return &JSONFormatter{}
	}
}

func (f *JSONFormatter) Output(result *core.AssessmentResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (f *CSVFormatter) Output(result *core.AssessmentResult) error {
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	// Headers
	headers := []string{"Domain", "Overall Score", "Level", "Timestamp", "Duration"}
	for probeName := range result.ProbeResults {
		headers = append(headers, probeName+" Score")
		headers = append(headers, probeName+" Status")
	}
	writer.Write(headers)

	// Data
	row := []string{
		result.Domain,
		fmt.Sprintf("%.4f", result.Score),
		result.Level,
		result.Timestamp.Format(time.RFC3339),
		result.Duration.String(),
	}

	for _, probeResult := range result.ProbeResults {
		row = append(row, fmt.Sprintf("%.4f", probeResult.Score))
		row = append(row, probeResult.Status)
	}
	
	writer.Write(row)
	return nil
}

// ProbeLevel represents the security level of a probe
type ProbeLevel int

const (
	LevelCritical ProbeLevel = iota
	LevelImportant
	LevelInformational
)

// getProbeLevel returns the security level for a probe
func getProbeLevel(probeName string) ProbeLevel {
	switch strings.ToLower(probeName) {
	case "tls security", "security headers":
		return LevelCritical
	case "https access", "dns security":
		return LevelImportant
	default:
		return LevelInformational
	}
}

// displayProbesByLevel displays probes grouped by security level
func displayProbesByLevel(probeResults map[string]*core.ProbeResult) {
	// Group probes by level
	critical := make(map[string]*core.ProbeResult)
	important := make(map[string]*core.ProbeResult)
	informational := make(map[string]*core.ProbeResult)
	
	for name, result := range probeResults {
		level := getProbeLevel(name)
		switch level {
		case LevelCritical:
			critical[name] = result
		case LevelImportant:
			important[name] = result
		case LevelInformational:
			informational[name] = result
		}
	}
	
	// Display Critical Security
	if len(critical) > 0 {
		color.Red("🚨 CRITICAL SECURITY")
		fmt.Println(strings.Repeat("━", 60))
		displayProbeGroup(critical)
		fmt.Println()
	}
	
	// Display Important Configuration
	if len(important) > 0 {
		color.Yellow("⚠️  IMPORTANT CONFIGURATION")
		fmt.Println(strings.Repeat("━", 60))
		displayProbeGroup(important)
		fmt.Println()
	}
	
	// Display Best Practices
	if len(informational) > 0 {
		color.Blue("ℹ️  BEST PRACTICES")
		fmt.Println(strings.Repeat("━", 60))
		displayProbeGroup(informational)
		fmt.Println()
	}
}

// displayProbeGroup displays a group of probes
func displayProbeGroup(probes map[string]*core.ProbeResult) {
	for name, probeResult := range probes {
		// Icon based on probe type
		icon := "🔍"
		switch strings.ToLower(name) {
		case "tls security":
			icon = "🔐"
		case "dns security":
			icon = "🌍"
		case "https access":
			icon = "🌐"
		case "security headers":
			icon = "🛡️"
		}
		
		// Status indicator
		status := "✅"
		statusColor := color.GreenString
		if probeResult.Score < 0.4 {
			status = "❌"
			statusColor = color.RedString
		} else if probeResult.Score < 0.8 {
			status = "⚠️"
			statusColor = color.YellowString
		}
		
		// Display probe result
		fmt.Printf("  %s %-20s %s %s (%.0f%%)\n", 
			icon, 
			name,
			status,
			statusColor(fmt.Sprintf("%.2f", probeResult.Score)),
			probeResult.Score*100)
		
		// Show key details
		if probeResult.Error != "" {
			color.Red("     Error: %s", probeResult.Error)
		} else if len(probeResult.Details) > 0 {
			// Show first 3 details
			count := 0
			for key, value := range probeResult.Details {
				if count >= 3 {
					break
				}
				fmt.Printf("     • %s: %v\n", key, value)
				count++
			}
		}
	}
}

func (f *ReportFormatter) Output(result *core.AssessmentResult) error {
	// Header
	color.Cyan("🔍 DQIX Assessment Report (Go Implementation)")
	color.Cyan("=" + strings.Repeat("=", 50))
	fmt.Println()

	// Basic info
	color.Green("📊 Assessment Summary:")
	fmt.Printf("  Domain: %s\n", result.Domain)
	fmt.Printf("  Overall Score: %.4f/1.0000\n", result.Score)
	fmt.Printf("  Quality Level: %s\n", result.Level)
	fmt.Printf("  Assessment Time: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Duration: %s\n", result.Duration)
	fmt.Printf("  Implementation: %s\n", result.Metadata["implementation"])
	fmt.Printf("  Version: %s\n", result.Metadata["version"])
	fmt.Println()

	// Probe details with 3-level hierarchy
	displayProbesByLevel(result.ProbeResults)

	// Level explanation
	color.Magenta("📈 Quality Level Guide:")
	levels := map[string]string{
		"A+": "95-100% - Exceptional security and compliance",
		"A":  "85-94% - Excellent security posture",
		"B":  "75-84% - Good security with minor improvements needed",
		"C":  "65-74% - Adequate security with several improvements needed",
		"D":  "55-64% - Below average security, significant improvements required",
		"E":  "45-54% - Poor security posture, immediate attention required",
		"F":  "0-44% - Critical security issues, urgent action required",
	}
	
	for level, description := range levels {
		marker := "  "
		if level == result.Level {
			marker = "→ "
			color.Green("%s%s: %s", marker, level, description)
		} else {
			fmt.Printf("%s%s: %s\n", marker, level, description)
		}
	}
	
	fmt.Println()
	color.Cyan("Generated by DQIX Go Implementation v%s", result.Metadata["version"])
	
	return nil
} 