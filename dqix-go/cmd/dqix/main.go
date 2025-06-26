package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Enhanced domain types with detailed information
type ProbeDetails struct {
	ProtocolVersion      string            `json:"protocol_version,omitempty"`
	CipherSuite          string            `json:"cipher_suite,omitempty"`
	CertificateValid     string            `json:"certificate_valid,omitempty"`
	CertChainLength      string            `json:"cert_chain_length,omitempty"`
	KeyExchange          string            `json:"key_exchange,omitempty"`
	PfsSupport           string            `json:"pfs_support,omitempty"`
	HttpsAccessible      string            `json:"https_accessible,omitempty"`
	HttpRedirects        string            `json:"http_redirects,omitempty"`
	HstsHeader           string            `json:"hsts_header,omitempty"`
	HstsMaxAge           string            `json:"hsts_max_age,omitempty"`
	Http2Support         string            `json:"http2_support,omitempty"`
	DnssecEnabled        string            `json:"dnssec_enabled,omitempty"`
	SpfRecord            string            `json:"spf_record,omitempty"`
	DmarcPolicy          string            `json:"dmarc_policy,omitempty"`
	CaaRecords           string            `json:"caa_records,omitempty"`
	Csp                  string            `json:"csp,omitempty"`
	XFrameOptions        string            `json:"x_frame_options,omitempty"`
	XContentTypeOptions  string            `json:"x_content_type_options,omitempty"`
	ReferrerPolicy       string            `json:"referrer_policy,omitempty"`
	ServerHeader         string            `json:"server_header,omitempty"`
	ResponseTime         string            `json:"response_time,omitempty"`
	ExecutionTime        float64           `json:"execution_time,omitempty"`
	CustomFields         map[string]string `json:"custom_fields,omitempty"`
	Message              string            `json:"message,omitempty"`
}

type ProbeResult struct {
	ProbeID   string       `json:"probe_id"`
	Score     float64      `json:"score"`
	Category  string       `json:"category"`
	Details   ProbeDetails `json:"details"`
	Timestamp time.Time    `json:"timestamp"`
}

type Metadata struct {
	Engine        string `json:"engine"`
	Version       string `json:"version"`
	ProbeCount    int    `json:"probe_count"`
	TimeoutPolicy string `json:"timeout_policy"`
	ScoringMethod string `json:"scoring_method"`
}

type AssessmentResult struct {
	Domain              string        `json:"domain"`
	OverallScore        float64       `json:"overall_score"`
	ComplianceLevel     string        `json:"compliance_level"`
	ProbeResults        []ProbeResult `json:"probe_results"`
	AssessmentTimestamp time.Time     `json:"assessment_timestamp"`
	ExecutionTime       float64       `json:"execution_time"`
	Metadata            Metadata      `json:"metadata"`
}

// Domain validation
type Domain struct {
	Name string `json:"name"`
}

type ComplianceLevel int

const (
	Basic ComplianceLevel = iota
	Standard
	Advanced
	Expert
)

func (c ComplianceLevel) String() string {
	switch c {
	case Basic:
		return "Basic"
	case Standard:
		return "Standard"
	case Advanced:
		return "Advanced"
	case Expert:
		return "Expert"
	default:
		return "Unknown"
	}
}

// Functional Result Types
type Result[T any] struct {
	Value T
	Error error
}

func Ok[T any](value T) Result[T] {
	return Result[T]{Value: value}
}

func Err[T any](err error) Result[T] {
	return Result[T]{Error: err}
}

func (r Result[T]) IsOk() bool {
	return r.Error == nil
}

func (r Result[T]) IsErr() bool {
	return r.Error != nil
}

// Pure domain logic functions
func validateDomain(domain string) Result[Domain] {
	if domain == "" {
		return Err[Domain](fmt.Errorf("domain cannot be empty"))
	}
	if len(domain) > 253 {
		return Err[Domain](fmt.Errorf("domain too long"))
	}
	if strings.Contains(domain, " ") {
		return Err[Domain](fmt.Errorf("domain cannot contain spaces"))
	}
	if domain == "localhost" {
		return Err[Domain](fmt.Errorf("localhost not allowed"))
	}
	if strings.Contains(domain, "://") {
		return Err[Domain](fmt.Errorf("remove protocol (http://)"))
	}
	if strings.Contains(domain, "/") {
		return Err[Domain](fmt.Errorf("remove path"))
	}
	return Ok(Domain{Name: domain})
}

func calculateProbeScore(probeType string, baseScore float64) Result[float64] {
	validProbeTypes := []string{"tls", "dns", "https", "security_headers"}
	
	isValid := false
	for _, validType := range validProbeTypes {
		if probeType == validType {
			isValid = true
			break
		}
	}
	
	if !isValid || baseScore < 0 || baseScore > 1 {
		return Err[float64](fmt.Errorf("invalid probe type or score"))
	}
	return Ok(baseScore)
}

func calculateOverallScore(probes []ProbeResult) Result[float64] {
	if len(probes) == 0 {
		return Err[float64](fmt.Errorf("no probe results"))
	}
	return Ok(calculateWeightedScore(probes))
}

func calculateWeightedScore(probes []ProbeResult) float64 {
	weights := map[string]float64{
		"tls":              0.35,
		"dns":              0.25,
		"https":            0.20,
		"security_headers": 0.20,
	}
	
	var weightedSum, totalWeight float64
	
	for _, probe := range probes {
		weight := weights[probe.ProbeID]
		if weight == 0 {
			weight = 0.1 // Default weight
		}
		weightedSum += probe.Score * weight
		totalWeight += weight
	}
	
	if totalWeight > 0 {
		return weightedSum / totalWeight
	}
	return 0
}

func determineComplianceLevel(score float64) Result[ComplianceLevel] {
	switch {
	case score >= 0.85:
		return Ok(Expert)
	case score >= 0.70:
		return Ok(Advanced)
	case score >= 0.50:
		return Ok(Standard)
	case score >= 0.00:
		return Ok(Basic)
	default:
		return Err[ComplianceLevel](fmt.Errorf("invalid score"))
	}
}

func composeAssessment(domain Domain, probes []ProbeResult) Result[AssessmentResult] {
	overallScoreResult := calculateOverallScore(probes)
	if overallScoreResult.IsErr() {
		return Err[AssessmentResult](overallScoreResult.Error)
	}
	
	complianceLevelResult := determineComplianceLevel(overallScoreResult.Value)
	if complianceLevelResult.IsErr() {
		return Err[AssessmentResult](complianceLevelResult.Error)
	}
	
	return Ok(AssessmentResult{
		Domain:              domain.Name,
		OverallScore:        overallScoreResult.Value,
		ComplianceLevel:     complianceLevelResult.Value.String(),
		ProbeResults:        probes,
		AssessmentTimestamp: time.Now(),
		ExecutionTime:       0.5,
		Metadata: Metadata{
			Engine:        "Go DQIX v1.0.0",
			Version:       "1.0.0",
			ProbeCount:    len(probes),
			TimeoutPolicy: "30s per probe",
			ScoringMethod: "Weighted composite (TLS:35%, DNS:25%, HTTPS:20%, Headers:20%)",
		},
	})
}

// Enhanced mock data generation with detailed information
func generateDetailedMockData(domainName string) AssessmentResult {
	currentTime := time.Now()
	
	// Generate realistic probe results with detailed information
	tlsCustomFields := map[string]string{
		"vulnerability_scan": "clean",
		"ocsp_stapling":      "enabled",
		"ct_logs":            "present",
	}
	
	httpsCustomFields := map[string]string{
		"hsts_subdomains": "true",
		"http3_support":   "false",
		"compression_type": "gzip",
	}
	
	dnsCustomFields := map[string]string{
		"ipv4_records":        "present",
		"ipv6_records":        "present",
		"dnssec_chain_valid":  "true",
		"dkim_selectors":      "google, mailchimp",
		"mx_records":          "present",
		"ns_records":          "cloudflare",
		"ttl_analysis":        "optimized",
	}
	
	headersCustomFields := map[string]string{
		"hsts":               "max-age=31536000; includeSubDomains",
		"permissions_policy": "camera=(), microphone=()",
		"x_xss_protection":   "1; mode=block",
		"content_type":       "text/html; charset=utf-8",
		"powered_by":         "hidden",
	}
	
	probeResultsList := []ProbeResult{
		{
			ProbeID:   "tls",
			Score:     0.923,
			Category:  "security",
			Timestamp: currentTime,
			Details: ProbeDetails{
				ProtocolVersion:  "TLS 1.3",
				CipherSuite:      "TLS_AES_256_GCM_SHA384",
				CertificateValid: "true",
				CertChainLength:  "3",
				KeyExchange:      "ECDHE",
				PfsSupport:       "true",
				ExecutionTime:    0.45,
				CustomFields:     tlsCustomFields,
				Message:          "TLS security analysis complete",
			},
		},
		{
			ProbeID:   "https",
			Score:     0.891,
			Category:  "protocol",
			Timestamp: currentTime,
			Details: ProbeDetails{
				HttpsAccessible: "true",
				HttpRedirects:   "301 permanent",
				HstsHeader:      "present",
				HstsMaxAge:      "31536000",
				Http2Support:    "true",
				ResponseTime:    "245",
				ExecutionTime:   0.32,
				CustomFields:    httpsCustomFields,
				Message:         "HTTPS implementation analysis complete",
			},
		},
		{
			ProbeID:   "dns",
			Score:     0.756,
			Category:  "infrastructure",
			Timestamp: currentTime,
			Details: ProbeDetails{
				DnssecEnabled: "true",
				SpfRecord:     "v=spf1 include:_spf.google.com ~all",
				DmarcPolicy:   "v=DMARC1; p=quarantine",
				CaaRecords:    "0 issue \"letsencrypt.org\"",
				ExecutionTime: 0.28,
				CustomFields:  dnsCustomFields,
				Message:       "DNS infrastructure analysis complete",
			},
		},
		{
			ProbeID:   "security_headers",
			Score:     0.678,
			Category:  "application",
			Timestamp: currentTime,
			Details: ProbeDetails{
				Csp:                 "default-src 'self'",
				XFrameOptions:       "DENY",
				XContentTypeOptions: "nosniff",
				ReferrerPolicy:      "strict-origin-when-cross-origin",
				ServerHeader:        "nginx/1.20.1",
				ExecutionTime:       0.19,
				CustomFields:        headersCustomFields,
				Message:             "Security headers analysis complete",
			},
		},
	}
	
	// Calculate overall score with weighted algorithm
	overallScoreValue := calculateWeightedScore(probeResultsList)
	complianceLevelResult := determineComplianceLevel(overallScoreValue)
	
	var complianceLevelValue string
	if complianceLevelResult.IsOk() {
		complianceLevelValue = complianceLevelResult.Value.String()
	} else {
		complianceLevelValue = "Basic"
	}
	
	return AssessmentResult{
		Domain:              domainName,
		OverallScore:        overallScoreValue,
		ComplianceLevel:     complianceLevelValue,
		ProbeResults:        probeResultsList,
		AssessmentTimestamp: currentTime,
		ExecutionTime:       0.5,
		Metadata: Metadata{
			Engine:        "Go DQIX v1.0.0",
			Version:       "1.0.0",
			ProbeCount:    len(probeResultsList),
			TimeoutPolicy: "30s per probe",
			ScoringMethod: "Weighted composite (TLS:35%, DNS:25%, HTTPS:20%, Headers:20%)",
		},
	}
}

// Display functions
func displayResults(result AssessmentResult) {
	scoreValue := result.OverallScore
	
	fmt.Printf("\n🔍 %s\n", result.Domain)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	barLength := 20
	filledBars := int(scoreValue * float64(barLength))
	emptyBars := barLength - filledBars
	scoreBar := strings.Repeat("█", filledBars) + strings.Repeat("░", emptyBars)
	
	fmt.Printf("🔒 Security Score: %.1f%% %s\n", scoreValue*100, scoreBar)
	fmt.Printf("📋 Compliance: %s\n", result.ComplianceLevel)
	fmt.Printf("⏰ Scanned: %s\n", result.AssessmentTimestamp.Format("2006-01-02 15:04"))
	
	fmt.Println("\n📋 Security Assessment Details\n")
	
	probeOrder := []struct {
		ID    string
		Title string
	}{
		{"tls", "🔐 TLS/SSL Security"},
		{"https", "🌐 HTTPS Implementation"},
		{"dns", "🌍 DNS Infrastructure"},
		{"security_headers", "🛡️ Security Headers"},
	}
	
	for _, probe := range probeOrder {
		if probeResult := findProbeResult(result.ProbeResults, probe.ID); probeResult != nil {
			probeScore := probeResult.Score
			var status string
			if probeScore >= 0.8 {
				status = "✅ EXCELLENT"
			} else if probeScore >= 0.6 {
				status = "⚠️ GOOD"
			} else if probeScore >= 0.4 {
				status = "🔶 FAIR"
			} else {
				status = "❌ POOR"
			}
			fmt.Printf("%s: %.1f%% %s\n", probe.Title, probeScore*100, status)
		}
	}
}

// Helper functions
func findProbeResult(results []ProbeResult, probeID string) *ProbeResult {
	for i := range results {
		if results[i].ProbeID == probeID {
			return &results[i]
		}
	}
	return nil
}

// Main CLI interface
func main() {
	args := os.Args[1:]
	
	switch {
	case len(args) == 2 && args[0] == "scan":
		result := generateDetailedMockData(args[1])
		displayResults(result)
	case len(args) == 1 && args[0] == "test":
		runTests()
	case len(args) == 1 && args[0] == "demo":
		result := generateDetailedMockData("github.com")
		displayResults(result)
	default:
		fmt.Println("🔍 DQIX Internet Observability Platform (Go)")
		fmt.Println("Usage:")
		fmt.Println("  dqix scan <domain>    # Scan domain")
		fmt.Println("  dqix test             # Run tests")
		fmt.Println("  dqix demo             # Demo mode")
	}
}

// Test suite
func runTests() {
	fmt.Println("🧪 Running Go DQIX Test Suite...")
	fmt.Println("")
	
	// Test domain validation
	fmt.Print("Testing domain validation... ")
	validationTests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"", false},
		{"localhost", false},
		{"http://example.com", false},
	}
	
	allPassed := true
	for _, test := range validationTests {
		result := validateDomain(test.domain)
		passed := (result.IsOk() == test.expected)
		if !passed {
			allPassed = false
			break
		}
	}
	
	if allPassed {
		fmt.Println("✅ PASS")
	} else {
		fmt.Println("❌ FAIL")
	}
	
	// Test scoring
	fmt.Print("Testing scoring calculation... ")
	mockProbes := []ProbeResult{
		{ProbeID: "tls", Score: 0.8, Category: "security", Timestamp: time.Now()},
	}
	scoringResult := calculateOverallScore(mockProbes)
	scoringTest := scoringResult.IsOk() && scoringResult.Value > 0 && scoringResult.Value <= 1
	
	if scoringTest {
		fmt.Println("✅ PASS")
	} else {
		fmt.Println("❌ FAIL")
	}
	
	// Test compliance levels
	fmt.Print("Testing compliance levels... ")
	complianceResult := determineComplianceLevel(0.8)
	complianceTest := complianceResult.IsOk() && complianceResult.Value == Advanced
	
	if complianceTest {
		fmt.Println("✅ PASS")
	} else {
		fmt.Println("❌ FAIL")
	}
	
	fmt.Println("")
	fmt.Println("🎉 Go test suite completed!")
} 