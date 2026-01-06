package redteam

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

type ReconConfig struct {
	Target  string
	Deep    bool
	Passive bool
	Stealth bool
}

type ReconResults struct {
	Subdomains     []string
	IPAddresses    []string
	OpenPorts      []int
	Technologies   []string
	SSLInfo        *SSLInfo
	WAFDetected    string
	Headers        map[string]string
	DNSRecords     map[string][]string
	EmailAddresses []string
	mu             sync.Mutex
}

type SSLInfo struct {
	Issuer     string
	Subject    string
	ValidFrom  time.Time
	ValidUntil time.Time
	DNSNames   []string
	Version    uint16
}

// RunAdvancedRecon performs comprehensive reconnaissance
func RunAdvancedRecon(target string, ports string) *ReconResults {
	results := &ReconResults{
		Headers:    make(map[string]string),
		DNSRecords: make(map[string][]string),
	}

	color.Green("🔍 Advanced Reconnaissance Module")
	color.Cyan("   Target: %s", target)
	color.Yellow("   🕵️  Gathering intelligence...\n")

	var wg sync.WaitGroup

	// DNS Enumeration
	wg.Add(1)
	go func() {
		defer wg.Done()
		dnsRecon(target, results)
	}()

	// SSL Certificate Analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		sslRecon(target, results)
	}()

	// Technology Detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		techDetection(target, results)
	}()

	// Subdomain Enumeration
	wg.Add(1)
	go func() {
		defer wg.Done()
		subdomainEnum(target, results)
	}()

	// HTTP Header Analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		headerAnalysis(target, results)
	}()

	wg.Wait()

	printReconResults(results)
	return results
}

func dnsRecon(target string, results *ReconResults) {
	color.Cyan("📋 DNS Enumeration...")

	recordTypes := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeMX,
		dns.TypeTXT,
		dns.TypeNS,
		dns.TypeCNAME,
		dns.TypeSOA,
	}

	c := new(dns.Client)
	m := new(dns.Msg)

	for _, rtype := range recordTypes {
		m.SetQuestion(dns.Fqdn(target), rtype)
		m.RecursionDesired = true

		r, _, err := c.Exchange(m, "8.8.8.8:53")
		if err != nil {
			continue
		}

		for _, ans := range r.Answer {
			results.mu.Lock()
			switch rtype {
			case dns.TypeA:
				if a, ok := ans.(*dns.A); ok {
					results.IPAddresses = append(results.IPAddresses, a.A.String())
					results.DNSRecords["A"] = append(results.DNSRecords["A"], a.A.String())
				}
			case dns.TypeAAAA:
				if aaaa, ok := ans.(*dns.AAAA); ok {
					results.IPAddresses = append(results.IPAddresses, aaaa.AAAA.String())
					results.DNSRecords["AAAA"] = append(results.DNSRecords["AAAA"], aaaa.AAAA.String())
				}
			case dns.TypeMX:
				if mx, ok := ans.(*dns.MX); ok {
					results.DNSRecords["MX"] = append(results.DNSRecords["MX"], mx.Mx)
				}
			case dns.TypeTXT:
				if txt, ok := ans.(*dns.TXT); ok {
					for _, t := range txt.Txt {
						results.DNSRecords["TXT"] = append(results.DNSRecords["TXT"], t)
					}
				}
			case dns.TypeNS:
				if ns, ok := ans.(*dns.NS); ok {
					results.DNSRecords["NS"] = append(results.DNSRecords["NS"], ns.Ns)
				}
			case dns.TypeCNAME:
				if cname, ok := ans.(*dns.CNAME); ok {
					results.DNSRecords["CNAME"] = append(results.DNSRecords["CNAME"], cname.Target)
				}
			}
			results.mu.Unlock()
		}
	}

	color.Green("   ✅ DNS enumeration complete")
}

func sslRecon(target string, results *ReconResults) {
	color.Cyan("🔐 SSL/TLS Certificate Analysis...")

	// Extract hostname
	hostname := target
	if strings.Contains(target, "://") {
		parts := strings.Split(target, "://")
		if len(parts) > 1 {
			hostname = strings.Split(parts[1], "/")[0]
		}
	}

	conn, err := tls.Dial("tcp", hostname+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		color.Yellow("   ⚠️  SSL connection failed: %v", err)
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]

		results.mu.Lock()
		results.SSLInfo = &SSLInfo{
			Issuer:     cert.Issuer.String(),
			Subject:    cert.Subject.String(),
			ValidFrom:  cert.NotBefore,
			ValidUntil: cert.NotAfter,
			DNSNames:   cert.DNSNames,
			Version:    conn.ConnectionState().Version,
		}
		results.mu.Unlock()

		// Extract subdomains from certificate
		for _, name := range cert.DNSNames {
			if name != target && !strings.HasPrefix(name, "*") {
				results.mu.Lock()
				results.Subdomains = append(results.Subdomains, name)
				results.mu.Unlock()
			}
		}
	}

	color.Green("   ✅ SSL analysis complete")
}

func techDetection(target string, results *ReconResults) {
	color.Cyan("🔧 Technology Stack Detection...")

	url := target
	if !strings.HasPrefix(target, "http") {
		url = "https://" + target
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		color.Yellow("   ⚠️  Could not connect: %v", err)
		return
	}
	defer resp.Body.Close()

	technologies := []string{}

	// Detect from headers
	if server := resp.Header.Get("Server"); server != "" {
		technologies = append(technologies, "Server: "+server)
	}

	if xPoweredBy := resp.Header.Get("X-Powered-By"); xPoweredBy != "" {
		technologies = append(technologies, "X-Powered-By: "+xPoweredBy)
	}

	if framework := resp.Header.Get("X-Framework"); framework != "" {
		technologies = append(technologies, "Framework: "+framework)
	}

	// Detect CDN
	if cf := resp.Header.Get("CF-Ray"); cf != "" {
		technologies = append(technologies, "CDN: Cloudflare")
	}

	if resp.Header.Get("X-Akamai-Transformed") != "" {
		technologies = append(technologies, "CDN: Akamai")
	}

	// Detect WAF
	wafHeaders := map[string]string{
		"CF-Ray":               "Cloudflare",
		"X-Sucuri-ID":          "Sucuri",
		"X-Akamai-Transformed": "Akamai",
		"Server":               "",
	}

	for header, wafName := range wafHeaders {
		if val := resp.Header.Get(header); val != "" {
			if wafName != "" {
				results.mu.Lock()
				results.WAFDetected = wafName
				results.mu.Unlock()
			} else if strings.Contains(strings.ToLower(val), "cloudflare") {
				results.mu.Lock()
				results.WAFDetected = "Cloudflare"
				results.mu.Unlock()
			}
		}
	}

	results.mu.Lock()
	results.Technologies = technologies
	results.mu.Unlock()

	color.Green("   ✅ Technology detection complete")
}

func subdomainEnum(target string, results *ReconResults) {
	color.Cyan("🌐 Subdomain Enumeration...")

	// Common subdomains to check
	commonSubdomains := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
		"admin", "portal", "api", "dev", "staging", "test", "vpn", "m", "blog",
		"shop", "forum", "support", "cdn", "static", "img", "images", "assets",
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Limit concurrent checks

	for _, sub := range commonSubdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fullDomain := fmt.Sprintf("%s.%s", subdomain, target)

			// Try DNS lookup
			_, err := net.LookupHost(fullDomain)
			if err == nil {
				results.mu.Lock()
				results.Subdomains = append(results.Subdomains, fullDomain)
				results.mu.Unlock()
			}
		}(sub)
	}

	wg.Wait()
	color.Green("   ✅ Found %d subdomains", len(results.Subdomains))
}

func headerAnalysis(target string, results *ReconResults) {
	color.Cyan("📊 HTTP Header Analysis...")

	url := target
	if !strings.HasPrefix(target, "http") {
		url = "https://" + target
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	results.mu.Lock()
	for key, values := range resp.Header {
		if len(values) > 0 {
			results.Headers[key] = values[0]
		}
	}
	results.mu.Unlock()

	// Security header analysis
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
	}

	missingHeaders := []string{}
	for _, header := range securityHeaders {
		if resp.Header.Get(header) == "" {
			missingHeaders = append(missingHeaders, header)
		}
	}

	if len(missingHeaders) > 0 {
		color.Yellow("   ⚠️  Missing security headers: %v", missingHeaders)
	}

	color.Green("   ✅ Header analysis complete")
}

func printReconResults(results *ReconResults) {
	fmt.Println()
	color.Green("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	color.Green("           RECONNAISSANCE RESULTS")
	color.Green("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// IP Addresses
	if len(results.IPAddresses) > 0 {
		color.Cyan("\n🌐 IP Addresses:")
		for _, ip := range results.IPAddresses {
			color.White("   • %s", ip)
		}
	}

	// DNS Records
	if len(results.DNSRecords) > 0 {
		color.Cyan("\n📋 DNS Records:")
		for rtype, records := range results.DNSRecords {
			color.Yellow("   %s:", rtype)
			for _, record := range records {
				color.White("     • %s", record)
			}
		}
	}

	// SSL Information
	if results.SSLInfo != nil {
		color.Cyan("\n🔐 SSL Certificate:")
		color.White("   Issuer: %s", results.SSLInfo.Issuer)
		color.White("   Subject: %s", results.SSLInfo.Subject)
		color.White("   Valid: %s - %s",
			results.SSLInfo.ValidFrom.Format("2006-01-02"),
			results.SSLInfo.ValidUntil.Format("2006-01-02"))
		if len(results.SSLInfo.DNSNames) > 0 {
			color.Yellow("   SANs:")
			for _, name := range results.SSLInfo.DNSNames {
				color.White("     • %s", name)
			}
		}
	}

	// Subdomains
	if len(results.Subdomains) > 0 {
		color.Cyan("\n🌐 Discovered Subdomains:")
		for _, sub := range results.Subdomains {
			color.White("   • %s", sub)
		}
	}

	// Technologies
	if len(results.Technologies) > 0 {
		color.Cyan("\n🔧 Technology Stack:")
		for _, tech := range results.Technologies {
			color.White("   • %s", tech)
		}
	}

	// WAF Detection
	if results.WAFDetected != "" {
		color.Yellow("\n🛡️  WAF Detected: %s", results.WAFDetected)
	}

	// Security Headers
	if len(results.Headers) > 0 {
		color.Cyan("\n📊 Key HTTP Headers:")
		securityHeaders := []string{
			"Server", "X-Powered-By", "Strict-Transport-Security",
			"Content-Security-Policy", "X-Frame-Options",
		}
		for _, header := range securityHeaders {
			if val, ok := results.Headers[header]; ok {
				color.White("   %s: %s", header, val)
			}
		}
	}

	color.Green("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}
