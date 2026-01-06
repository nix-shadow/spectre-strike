package recon

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// ReconResult contains reconnaissance results
type ReconResult struct {
	Target          string
	IPAddresses     []string
	ServerInfo      ServerInfo
	Headers         map[string][]string
	Technologies    []string
	Vulnerabilities []string
	CDNDetected     bool
	CDNProvider     string
	WAFDetected     bool
	WAFType         string
	SecurityHeaders SecurityHeaders
	Ports           []PortResult
	Subdomains      []string
	ScanTime        time.Duration
}

// ServerInfo contains server information
type ServerInfo struct {
	Server        string
	PoweredBy     string
	Framework     string
	Language      string
	CloudProvider string
}

// SecurityHeaders contains security header analysis
type SecurityHeaders struct {
	HSTS              bool
	ContentSecurity   bool
	XFrameOptions     bool
	XContentType      bool
	ReferrerPolicy    bool
	PermissionsPolicy bool
	Score             int
}

// PortResult contains port scan results
type PortResult struct {
	Port    int
	Open    bool
	Service string
	Banner  string
}

// Scanner performs reconnaissance
type Scanner struct {
	timeout    time.Duration
	maxThreads int
	userAgent  string
}

// NewScanner creates a new scanner
func NewScanner(timeout time.Duration, maxThreads int) *Scanner {
	return &Scanner{
		timeout:    timeout,
		maxThreads: maxThreads,
		userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

// Scan performs comprehensive reconnaissance
func (s *Scanner) Scan(target string) (*ReconResult, error) {
	color.Cyan("\n🔍 Starting reconnaissance on %s...\n", target)
	startTime := time.Now()

	result := &ReconResult{
		Target:          target,
		IPAddresses:     make([]string, 0),
		Technologies:    make([]string, 0),
		Vulnerabilities: make([]string, 0),
		Ports:           make([]PortResult, 0),
		Subdomains:      make([]string, 0),
		Headers:         make(map[string][]string),
	}

	// DNS resolution
	color.Yellow("  ├─ Resolving DNS...")
	ips, err := s.resolveDNS(target)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %v", err)
	}
	result.IPAddresses = ips
	color.Green("  │  ✓ Found %d IP(s): %s", len(ips), strings.Join(ips, ", "))

	// HTTP reconnaissance
	color.Yellow("  ├─ Analyzing HTTP/HTTPS...")
	if err := s.httpRecon(target, result); err != nil {
		color.Red("  │  ✗ HTTP recon failed: %v", err)
	} else {
		color.Green("  │  ✓ HTTP analysis complete")
	}

	// Technology detection
	color.Yellow("  ├─ Detecting technologies...")
	s.detectTechnologies(result)
	if len(result.Technologies) > 0 {
		color.Green("  │  ✓ Detected: %s", strings.Join(result.Technologies, ", "))
	}

	// Security analysis
	color.Yellow("  ├─ Analyzing security...")
	s.analyzeSecurityHeaders(result)
	color.Green("  │  ✓ Security score: %d/100", result.SecurityHeaders.Score)

	// Port scanning
	color.Yellow("  ├─ Scanning common ports...")
	s.scanPorts(ips[0], result)
	openPorts := 0
	for _, p := range result.Ports {
		if p.Open {
			openPorts++
		}
	}
	color.Green("  │  ✓ Found %d open port(s)", openPorts)

	// WAF detection
	color.Yellow("  ├─ Detecting WAF/CDN...")
	s.detectWAF(target, result)
	if result.WAFDetected {
		color.Yellow("  │  ⚠ WAF detected: %s", result.WAFType)
	}
	if result.CDNDetected {
		color.Cyan("  │  ℹ CDN detected: %s", result.CDNProvider)
	}

	result.ScanTime = time.Since(startTime)
	color.Green("\n✅ Reconnaissance complete in %s\n", result.ScanTime)

	return result, nil
}

func (s *Scanner) resolveDNS(target string) ([]string, error) {
	// Remove protocol if present
	host := strings.TrimPrefix(target, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.Split(host, "/")[0]
	host = strings.Split(host, ":")[0]

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil {
			result = append(result, ip.String())
		}
	}

	return result, nil
}

func (s *Scanner) httpRecon(target string, result *ReconResult) error {
	client := &http.Client{
		Timeout: s.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Ensure target has protocol
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", s.userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	// Store headers
	result.Headers = resp.Header

	// Extract server info
	result.ServerInfo.Server = resp.Header.Get("Server")
	result.ServerInfo.PoweredBy = resp.Header.Get("X-Powered-By")

	return nil
}

func (s *Scanner) detectTechnologies(result *ReconResult) {
	// Detect from headers
	technologies := make(map[string]bool)

	if server := result.ServerInfo.Server; server != "" {
		server = strings.ToLower(server)
		if strings.Contains(server, "nginx") {
			technologies["Nginx"] = true
		} else if strings.Contains(server, "apache") {
			technologies["Apache"] = true
		} else if strings.Contains(server, "cloudflare") {
			technologies["Cloudflare"] = true
			result.CDNDetected = true
			result.CDNProvider = "Cloudflare"
		} else if strings.Contains(server, "microsoft-iis") {
			technologies["IIS"] = true
		}
	}

	if poweredBy := result.ServerInfo.PoweredBy; poweredBy != "" {
		poweredBy = strings.ToLower(poweredBy)
		if strings.Contains(poweredBy, "php") {
			technologies["PHP"] = true
		} else if strings.Contains(poweredBy, "asp.net") {
			technologies["ASP.NET"] = true
		} else if strings.Contains(poweredBy, "express") {
			technologies["Express.js"] = true
		}
	}

	// Check for various headers
	for key := range result.Headers {
		key = strings.ToLower(key)
		if strings.HasPrefix(key, "x-aspnet") {
			technologies["ASP.NET"] = true
		} else if strings.HasPrefix(key, "x-drupal") {
			technologies["Drupal"] = true
		} else if strings.HasPrefix(key, "x-wordpress") {
			technologies["WordPress"] = true
		}
	}

	// Convert to slice
	for tech := range technologies {
		result.Technologies = append(result.Technologies, tech)
	}
}

func (s *Scanner) analyzeSecurityHeaders(result *ReconResult) {
	score := 0

	if _, ok := result.Headers["Strict-Transport-Security"]; ok {
		result.SecurityHeaders.HSTS = true
		score += 20
	}

	if _, ok := result.Headers["Content-Security-Policy"]; ok {
		result.SecurityHeaders.ContentSecurity = true
		score += 20
	}

	if _, ok := result.Headers["X-Frame-Options"]; ok {
		result.SecurityHeaders.XFrameOptions = true
		score += 20
	}

	if _, ok := result.Headers["X-Content-Type-Options"]; ok {
		result.SecurityHeaders.XContentType = true
		score += 20
	}

	if _, ok := result.Headers["Referrer-Policy"]; ok {
		result.SecurityHeaders.ReferrerPolicy = true
		score += 10
	}

	if _, ok := result.Headers["Permissions-Policy"]; ok {
		result.SecurityHeaders.PermissionsPolicy = true
		score += 10
	}

	result.SecurityHeaders.Score = score

	// Check for vulnerabilities
	if !result.SecurityHeaders.HSTS {
		result.Vulnerabilities = append(result.Vulnerabilities, "Missing HSTS header")
	}
	if !result.SecurityHeaders.ContentSecurity {
		result.Vulnerabilities = append(result.Vulnerabilities, "Missing CSP header")
	}
	if !result.SecurityHeaders.XFrameOptions {
		result.Vulnerabilities = append(result.Vulnerabilities, "Missing X-Frame-Options (clickjacking risk)")
	}
}

func (s *Scanner) scanPorts(ip string, result *ReconResult) {
	commonPorts := []int{80, 443, 8080, 8443, 3000, 5000, 8000, 8888}

	var wg sync.WaitGroup
	resultChan := make(chan PortResult, len(commonPorts))

	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			resultChan <- s.scanPort(ip, p)
		}(port)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for portResult := range resultChan {
		result.Ports = append(result.Ports, portResult)
	}
}

func (s *Scanner) scanPort(ip string, port int) PortResult {
	result := PortResult{
		Port: port,
		Open: false,
	}

	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return result
	}
	conn.Close()

	result.Open = true

	// Identify service
	switch port {
	case 80:
		result.Service = "HTTP"
	case 443:
		result.Service = "HTTPS"
	case 8080, 8000, 3000, 5000, 8888:
		result.Service = "HTTP (Alt)"
	case 8443:
		result.Service = "HTTPS (Alt)"
	default:
		result.Service = "Unknown"
	}

	return result
}

func (s *Scanner) detectWAF(target string, result *ReconResult) {
	// Check headers for WAF signatures
	for key, values := range result.Headers {
		key = strings.ToLower(key)
		value := strings.ToLower(strings.Join(values, " "))

		if strings.Contains(key, "cf-ray") || strings.Contains(value, "cloudflare") {
			result.WAFDetected = true
			result.WAFType = "Cloudflare"
			result.CDNDetected = true
			result.CDNProvider = "Cloudflare"
			return
		} else if strings.Contains(key, "x-sucuri") || strings.Contains(value, "sucuri") {
			result.WAFDetected = true
			result.WAFType = "Sucuri"
			return
		} else if strings.Contains(value, "incapsula") || strings.Contains(value, "imperva") {
			result.WAFDetected = true
			result.WAFType = "Imperva Incapsula"
			return
		} else if strings.Contains(key, "akamai") || strings.Contains(value, "akamai") {
			result.WAFDetected = true
			result.WAFType = "Akamai"
			result.CDNDetected = true
			result.CDNProvider = "Akamai"
			return
		}
	}
}

// PrintReport prints a formatted report
func (r *ReconResult) PrintReport() {
	color.Cyan("\n╔════════════════════════════════════════════════════════════╗")
	color.Cyan("║           RECONNAISSANCE REPORT                            ║")
	color.Cyan("╚════════════════════════════════════════════════════════════╝\n")

	color.Yellow("🎯 Target: %s", r.Target)
	color.White("🌐 IP Addresses: %s", strings.Join(r.IPAddresses, ", "))

	if r.ServerInfo.Server != "" {
		color.White("🖥️  Server: %s", r.ServerInfo.Server)
	}
	if r.ServerInfo.PoweredBy != "" {
		color.White("⚡ Powered By: %s", r.ServerInfo.PoweredBy)
	}

	if len(r.Technologies) > 0 {
		color.Cyan("\n📦 Technologies Detected:")
		for _, tech := range r.Technologies {
			color.White("  • %s", tech)
		}
	}

	color.Cyan("\n🔒 Security Analysis:")
	color.White("  • Security Score: %d/100", r.SecurityHeaders.Score)
	color.White("  • HSTS: %v", r.SecurityHeaders.HSTS)
	color.White("  • CSP: %v", r.SecurityHeaders.ContentSecurity)
	color.White("  • X-Frame-Options: %v", r.SecurityHeaders.XFrameOptions)

	if len(r.Vulnerabilities) > 0 {
		color.Red("\n⚠️  Potential Vulnerabilities:")
		for _, vuln := range r.Vulnerabilities {
			color.Red("  • %s", vuln)
		}
	}

	if r.WAFDetected || r.CDNDetected {
		color.Yellow("\n🛡️  Protection Detected:")
		if r.WAFDetected {
			color.Yellow("  • WAF: %s", r.WAFType)
		}
		if r.CDNDetected {
			color.Yellow("  • CDN: %s", r.CDNProvider)
		}
	}

	color.Cyan("\n🔌 Open Ports:")
	for _, port := range r.Ports {
		if port.Open {
			color.Green("  • %d (%s)", port.Port, port.Service)
		}
	}

	color.White("\n⏱️  Scan completed in: %s\n", r.ScanTime)
}
