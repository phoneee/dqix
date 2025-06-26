package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dqix-org/dqix/internal/probes"
	"github.com/dqix-org/dqix/pkg/dsl"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

type Assessor struct {
	config   *Config
	probes   []probes.Probe
	executor *probes.Executor
}

type Config struct {
	DSLPath     string            `yaml:"dsl_path"`
	Timeout     time.Duration     `yaml:"timeout"`
	Concurrent  int               `yaml:"concurrent"`
	ProbeConfig map[string]interface{} `yaml:"probe_config"`
}

type AssessmentResult struct {
	Domain      string                    `json:"domain"`
	Score       float64                   `json:"score"`
	Level       string                    `json:"level"`
	Timestamp   time.Time                 `json:"timestamp"`
	ProbeResults map[string]*probes.Result `json:"probe_results"`
	Duration    time.Duration             `json:"duration"`
	Metadata    map[string]interface{}    `json:"metadata"`
}

func NewAssessor() *Assessor {
	return &Assessor{
		config: &Config{
			DSLPath:    "../../dsl/enhanced_probe_definition.yaml",
			Timeout:    30 * time.Second,
			Concurrent: 4,
		},
		executor: probes.NewExecutor(),
	}
}

func (a *Assessor) LoadConfig(path string) error {
	// Load DSL configuration
	dslConfig, err := dsl.LoadDSL(a.config.DSLPath)
	if err != nil {
		return fmt.Errorf("failed to load DSL: %w", err)
	}

	// Initialize probes from DSL
	for _, probeConfig := range dslConfig.Probes {
		probe, err := probes.CreateProbe(probeConfig)
		if err != nil {
			return fmt.Errorf("failed to create probe %s: %w", probeConfig.Name, err)
		}
		a.probes = append(a.probes, probe)
	}

	return nil
}

func (a *Assessor) Assess(domain string) (*AssessmentResult, error) {
	startTime := time.Now()
	
	color.Blue("📊 Assessing domain: %s", domain)
	
	// Initialize default probes if not loaded from config
	if len(a.probes) == 0 {
		a.initializeDefaultProbes()
	}
	
	// Create progress bar
	bar := progressbar.NewOptions(len(a.probes),
		progressbar.OptionSetDescription("Running probes..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerHead:    "█",
			SaucerPadding: "░",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetWidth(50),
	)
	
	// Run probes concurrently
	ctx, cancel := context.WithTimeout(context.Background(), a.config.Timeout)
	defer cancel()
	
	results := make(map[string]*probes.Result)
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	semaphore := make(chan struct{}, a.config.Concurrent)
	
	for _, probe := range a.probes {
		wg.Add(1)
		go func(p probes.Probe) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			result, err := a.executor.Execute(ctx, p, domain)
			if err != nil {
				result = &probes.Result{
					Name:    p.Name(),
					Score:   0.0,
					Status:  "error",
					Error:   err.Error(),
					Details: map[string]interface{}{"error": err.Error()},
				}
			}
			
			mu.Lock()
			results[p.Name()] = result
			mu.Unlock()
			
			bar.Add(1)
		}(probe)
	}
	
	wg.Wait()
	bar.Finish()
	
	// Calculate overall score
	overallScore := a.calculateOverallScore(results)
	level := a.calculateLevel(overallScore)
	
	return &AssessmentResult{
		Domain:       domain,
		Score:        overallScore,
		Level:        level,
		Timestamp:    startTime,
		ProbeResults: results,
		Duration:     time.Since(startTime),
		Metadata: map[string]interface{}{
			"implementation": "go",
			"version":        "1.2.0",
			"probes_count":   len(a.probes),
		},
	}, nil
}

func (a *Assessor) Benchmark(domains []string) error {
	color.Yellow("🚀 Starting Go Performance Benchmark")
	color.White("Domains: %v", domains)
	
	startTime := time.Now()
	
	// Sequential benchmark
	color.Cyan("\n📈 Sequential Processing:")
	seqStart := time.Now()
	for i, domain := range domains {
		fmt.Printf("  [%d/%d] %s", i+1, len(domains), domain)
		_, err := a.Assess(domain)
		if err != nil {
			color.Red(" ❌ Error: %v", err)
		} else {
			color.Green(" ✅ Complete")
		}
	}
	seqDuration := time.Since(seqStart)
	
	// Concurrent benchmark
	color.Cyan("\n⚡ Concurrent Processing:")
	concStart := time.Now()
	
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.config.Concurrent)
	
	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			fmt.Printf("  [%d/%d] %s", idx+1, len(domains), d)
			_, err := a.Assess(d)
			if err != nil {
				color.Red(" ❌ Error: %v", err)
			} else {
				color.Green(" ✅ Complete")
			}
		}(i, domain)
	}
	
	wg.Wait()
	concDuration := time.Since(concStart)
	
	// Results
	color.Green("\n📊 Benchmark Results:")
	color.White("  Sequential: %v (%.2f domains/sec)", seqDuration, float64(len(domains))/seqDuration.Seconds())
	color.White("  Concurrent: %v (%.2f domains/sec)", concDuration, float64(len(domains))/concDuration.Seconds())
	color.White("  Speedup: %.2fx", seqDuration.Seconds()/concDuration.Seconds())
	color.White("  Total time: %v", time.Since(startTime))
	
	return nil
}

func (a *Assessor) initializeDefaultProbes() {
	// Initialize default probes
	a.probes = []probes.Probe{
		probes.NewTLSProbe(),
		probes.NewDNSProbe(),
		probes.NewHTTPSProbe(),
		probes.NewSecurityHeadersProbe(),
	}
}

func (a *Assessor) calculateOverallScore(results map[string]*probes.Result) float64 {
	if len(results) == 0 {
		return 0.0
	}
	
	totalScore := 0.0
	totalWeight := 0.0
	
	for _, result := range results {
		weight := 1.0 // Default weight, should come from DSL
		totalScore += result.Score * weight
		totalWeight += weight
	}
	
	return totalScore / totalWeight
}

func (a *Assessor) calculateLevel(score float64) string {
	switch {
	case score >= 0.95:
		return "A+"
	case score >= 0.85:
		return "A"
	case score >= 0.75:
		return "B"
	case score >= 0.65:
		return "C"
	case score >= 0.55:
		return "D"
	case score >= 0.45:
		return "E"
	default:
		return "F"
	}
} 