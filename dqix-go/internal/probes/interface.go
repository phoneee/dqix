package probes

import (
	"context"
	"fmt"
	"time"
)

// Probe interface that all probes must implement
type Probe interface {
	Name() string
	Category() string
	Execute(ctx context.Context, domain string) (*Result, error)
	Weight() float64
	Timeout() time.Duration
}

// Result represents the result of a probe execution
type Result struct {
	Name      string                 `json:"name"`
	Category  string                 `json:"category"`
	Score     float64                `json:"score"`
	Status    string                 `json:"status"`
	Message   string                 `json:"message"`
	Error     string                 `json:"error,omitempty"`
	Details   map[string]interface{} `json:"details"`
	Duration  time.Duration          `json:"duration"`
	Timestamp time.Time              `json:"timestamp"`
}

// BaseProbe provides common functionality for all probes
type BaseProbe struct {
	name     string
	category string
	weight   float64
	timeout  time.Duration
}

func NewBaseProbe(name, category string, weight float64, timeout time.Duration) *BaseProbe {
	return &BaseProbe{
		name:     name,
		category: category,
		weight:   weight,
		timeout:  timeout,
	}
}

func (b *BaseProbe) Name() string {
	return b.name
}

func (b *BaseProbe) Category() string {
	return b.category
}

func (b *BaseProbe) Weight() float64 {
	return b.weight
}

func (b *BaseProbe) Timeout() time.Duration {
	return b.timeout
}

// CreateProbe factory function to create probes from configuration
func CreateProbe(config ProbeConfig) (Probe, error) {
	switch config.Type {
	case "tls":
		return NewTLSProbe(), nil
	case "dns":
		return NewDNSProbe(), nil
	case "https":
		return NewHTTPSProbe(), nil
	case "security_headers":
		return NewSecurityHeadersProbe(), nil
	default:
		return nil, fmt.Errorf("unknown probe type: %s", config.Type)
	}
}

type ProbeConfig struct {
	Name     string                 `yaml:"name"`
	Type     string                 `yaml:"type"`
	Category string                 `yaml:"category"`
	Weight   float64                `yaml:"weight"`
	Config   map[string]interface{} `yaml:"config"`
} 