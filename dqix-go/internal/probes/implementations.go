package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// TLS Probe
type TLSProbe struct {
	*BaseProbe
}

func NewTLSProbe() *TLSProbe {
	return &TLSProbe{
		BaseProbe: NewBaseProbe("TLS Security", "security", 1.5, 10*time.Second),  // Critical Security - aligned with shared-config.yaml
	}
}

func (p *TLSProbe) Execute(ctx context.Context, domain string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Name:      p.Name(),
		Category:  p.Category(),
		Timestamp: start,
		Details:   make(map[string]interface{}),
	}

	// Test TLS connection
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		ServerName: domain,
	})
	
	if err != nil {
		result.Score = 0.0
		result.Status = "failed"
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	score := 0.0
	
	// Check TLS version
	if state.Version >= tls.VersionTLS12 {
		score += 0.3
		result.Details["tls_version"] = "TLS 1.2+"
	} else {
		result.Details["tls_version"] = "TLS < 1.2"
	}
	
	// Check certificate validity
	for _, cert := range state.PeerCertificates {
		if time.Now().Before(cert.NotAfter) {
			score += 0.3
			result.Details["cert_valid"] = true
			break
		}
	}
	
	// Check cipher suite strength
	if state.CipherSuite != 0 {
		score += 0.4
		result.Details["cipher_suite"] = tls.CipherSuiteName(state.CipherSuite)
	}

	result.Score = score
	result.Status = "success"
	result.Message = fmt.Sprintf("TLS Score: %.1f/1.0", score)
	result.Duration = time.Since(start)
	
	return result, nil
}

// DNS Probe
type DNSProbe struct {
	*BaseProbe
}

func NewDNSProbe() *DNSProbe {
	return &DNSProbe{
		BaseProbe: NewBaseProbe("DNS Security", "security", 1.2, 10*time.Second),  // Important Configuration - aligned with shared-config.yaml
	}
}

func (p *DNSProbe) Execute(ctx context.Context, domain string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Name:      p.Name(),
		Category:  p.Category(),
		Timestamp: start,
		Details:   make(map[string]interface{}),
	}

	score := 0.0
	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	// Check DNSSEC
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.SetEdns0(4096, true)
	
	resp, _, err := client.Exchange(msg, "8.8.8.8:53")
	if err == nil && resp.AuthenticatedData {
		score += 0.4
		result.Details["dnssec"] = true
	} else {
		result.Details["dnssec"] = false
	}

	// Check SPF record
	txtMsg := new(dns.Msg)
	txtMsg.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	txtResp, _, err := client.Exchange(txtMsg, "8.8.8.8:53")
	
	if err == nil {
		for _, record := range txtResp.Answer {
			if txt, ok := record.(*dns.TXT); ok {
				for _, str := range txt.Txt {
					if strings.HasPrefix(str, "v=spf1") {
						score += 0.3
						result.Details["spf_record"] = true
						break
					}
				}
			}
		}
	}

	// Check DMARC record
	dmarcMsg := new(dns.Msg)
	dmarcMsg.SetQuestion(dns.Fqdn("_dmarc."+domain), dns.TypeTXT)
	dmarcResp, _, err := client.Exchange(dmarcMsg, "8.8.8.8:53")
	
	if err == nil {
		for _, record := range dmarcResp.Answer {
			if txt, ok := record.(*dns.TXT); ok {
				for _, str := range txt.Txt {
					if strings.HasPrefix(str, "v=DMARC1") {
						score += 0.3
						result.Details["dmarc_record"] = true
						break
					}
				}
			}
		}
	}

	result.Score = score
	result.Status = "success"
	result.Message = fmt.Sprintf("DNS Score: %.1f/1.0", score)
	result.Duration = time.Since(start)
	
	return result, nil
}

// HTTPS Probe
type HTTPSProbe struct {
	*BaseProbe
}

func NewHTTPSProbe() *HTTPSProbe {
	return &HTTPSProbe{
		BaseProbe: NewBaseProbe("HTTPS Access", "security", 1.2, 10*time.Second),  // Important Configuration - aligned with shared-config.yaml
	}
}

func (p *HTTPSProbe) Execute(ctx context.Context, domain string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Name:      p.Name(),
		Category:  p.Category(),
		Timestamp: start,
		Details:   make(map[string]interface{}),
	}

	score := 0.0
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test HTTPS accessibility
	httpsURL := "https://" + domain
	resp, err := client.Get(httpsURL)
	if err == nil && resp.StatusCode < 400 {
		score += 0.5
		result.Details["https_accessible"] = true
		resp.Body.Close()
	} else {
		result.Details["https_accessible"] = false
	}

	// Test HTTP to HTTPS redirect
	httpURL := "http://" + domain
	httpResp, err := client.Get(httpURL)
	if err == nil {
		if httpResp.StatusCode >= 300 && httpResp.StatusCode < 400 {
			location := httpResp.Header.Get("Location")
			if strings.HasPrefix(location, "https://") {
				score += 0.5
				result.Details["http_redirect"] = true
			}
		}
		httpResp.Body.Close()
	}

	result.Score = score
	result.Status = "success"
	result.Message = fmt.Sprintf("HTTPS Score: %.1f/1.0", score)
	result.Duration = time.Since(start)
	
	return result, nil
}

// Security Headers Probe
type SecurityHeadersProbe struct {
	*BaseProbe
}

func NewSecurityHeadersProbe() *SecurityHeadersProbe {
	return &SecurityHeadersProbe{
		BaseProbe: NewBaseProbe("Security Headers", "security", 1.5, 10*time.Second),  // Critical Security - aligned with shared-config.yaml
	}
}

func (p *SecurityHeadersProbe) Execute(ctx context.Context, domain string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Name:      p.Name(),
		Category:  p.Category(),
		Timestamp: start,
		Details:   make(map[string]interface{}),
	}

	score := 0.0
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get("https://" + domain)
	if err != nil {
		result.Score = 0.0
		result.Status = "failed"
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, nil
	}
	defer resp.Body.Close()

	headers := map[string]string{
		"Strict-Transport-Security": "HSTS",
		"Content-Security-Policy":   "CSP",
		"X-Frame-Options":          "X-Frame-Options",
		"X-Content-Type-Options":   "X-Content-Type-Options",
		"Referrer-Policy":          "Referrer-Policy",
	}

	for header, name := range headers {
		if resp.Header.Get(header) != "" {
			score += 0.2
			result.Details[strings.ToLower(strings.ReplaceAll(name, "-", "_"))] = true
		} else {
			result.Details[strings.ToLower(strings.ReplaceAll(name, "-", "_"))] = false
		}
	}

	result.Score = score
	result.Status = "success"
	result.Message = fmt.Sprintf("Security Headers Score: %.1f/1.0", score)
	result.Duration = time.Since(start)
	
	return result, nil
} 