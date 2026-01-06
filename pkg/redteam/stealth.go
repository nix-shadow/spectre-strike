package redteam

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/net/proxy"
)

type StealthConfig struct {
	Target    string
	Duration  time.Duration
	Proxy     string
	Obfuscate bool
	NoLogs    bool
	UseJitter bool
	UseTor    bool
}

type StealthStats struct {
	Requests  int
	Success   int
	Failed    int
	Blocked   int
	BytesSent int64
	BytesRecv int64
	mu        sync.Mutex
}

// RunStealthAttack performs anti-detection attack with traffic obfuscation
func RunStealthAttack(config StealthConfig) error {
	stats := &StealthStats{}
	startTime := time.Now()

	color.Green("🕵️  Stealth Attack Mode Activated")
	color.Cyan("   Target: %s", config.Target)
	color.Cyan("   Proxy: %s", config.Proxy)
	color.Yellow("   🔒 Anti-forensics: %v", config.NoLogs)
	color.Yellow("   🎭 Traffic obfuscation: %v", config.Obfuscate)
	fmt.Println()

	// Create transport with obfuscation
	transport := createStealthTransport(config)
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	done := make(chan bool)
	go func() {
		time.Sleep(config.Duration)
		done <- true
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			printStealthStats(stats, time.Since(startTime))
			return nil
		case <-ticker.C:
			printStealthStats(stats, time.Since(startTime))
		default:
			// Random delay with jitter (100-3000ms)
			jitter := time.Duration(100+randInt(2900)) * time.Millisecond
			time.Sleep(jitter)

			if err := sendStealthRequest(client, config, stats); err != nil {
				stats.mu.Lock()
				stats.Failed++
				stats.mu.Unlock()
			}
		}
	}
}

func createStealthTransport(config StealthConfig) http.RoundTripper {
	// Custom TLS config to avoid fingerprinting
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		PreferServerCipherSuites: false,
		SessionTicketsDisabled:   false,
		Renegotiation:            tls.RenegotiateOnceAsClient,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   false,
		DisableCompression:  false,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		Proxy:               http.ProxyFromEnvironment,
	}

	// Use SOCKS5 proxy if specified
	if config.Proxy != "" {
		dialer, err := proxy.SOCKS5("tcp", config.Proxy, nil, proxy.Direct)
		if err == nil {
			transport.Dial = dialer.Dial
		}
	}

	return transport
}

func sendStealthRequest(client *http.Client, config StealthConfig, stats *StealthStats) error {
	req, err := http.NewRequest("GET", config.Target, nil)
	if err != nil {
		return err
	}

	// Apply stealth headers
	applyStealthHeaders(req, config)

	// Obfuscate payload if enabled
	if config.Obfuscate {
		obfuscateRequest(req)
	}

	stats.mu.Lock()
	stats.Requests++
	stats.mu.Unlock()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response (appears normal)
	body, _ := io.ReadAll(resp.Body)

	stats.mu.Lock()
	stats.BytesSent += int64(len(req.Header.Get("User-Agent")))
	stats.BytesRecv += int64(len(body))

	// Check if request was blocked
	if resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode == 503 {
		stats.Blocked++
	} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		stats.Success++
	} else {
		stats.Failed++
	}
	stats.mu.Unlock()

	return nil
}

func applyStealthHeaders(req *http.Request, config StealthConfig) {
	// Legitimate browser headers
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	}

	req.Header.Set("User-Agent", userAgents[randInt(len(userAgents))])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("DNT", "1")
	req.Header.Set("Cache-Control", "max-age=0")

	// Random referer from legitimate sites
	referers := []string{
		"https://www.google.com/",
		"https://www.bing.com/",
		"https://duckduckgo.com/",
		"https://www.reddit.com/",
		"https://news.ycombinator.com/",
	}
	req.Header.Set("Referer", referers[randInt(len(referers))])

	// Add realistic timing
	req.Header.Set("X-Request-Start", fmt.Sprintf("t=%d", time.Now().UnixMilli()))
}

func obfuscateRequest(req *http.Request) {
	// Add steganographic data in headers
	encodedData := generateEncodedPayload()
	req.Header.Set("X-Custom-Data", encodedData)

	// Add timing obfuscation
	req.Header.Set("X-Client-Time", fmt.Sprintf("%d", time.Now().UnixNano()))

	// Randomize query parameters
	if !strings.Contains(req.URL.RawQuery, "?") {
		randomParams := generateRandomParams()
		req.URL.RawQuery = randomParams
	}
}

func generateEncodedPayload() string {
	data := make([]byte, 32)
	rand.Read(data)
	return base64.StdEncoding.EncodeToString(data)
}

func generateRandomParams() string {
	params := url.Values{}
	params.Add("utm_source", randomString(8))
	params.Add("utm_medium", randomString(6))
	params.Add("session", randomString(16))
	params.Add("_t", fmt.Sprintf("%d", time.Now().Unix()))
	return params.Encode()
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[randInt(len(charset))]
	}
	return string(b)
}

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	return n % max
}

func printStealthStats(stats *StealthStats, elapsed time.Duration) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	detectionRate := float64(stats.Blocked) / float64(stats.Requests) * 100
	if stats.Requests == 0 {
		detectionRate = 0
	}

	color.Cyan("\r🕵️  Requests: %d | Success: %d | Blocked: %d | Detection: %.1f%% | Elapsed: %s",
		stats.Requests, stats.Success, stats.Blocked, detectionRate, elapsed.Round(time.Second))
}

// AntiForensics clears local traces
func AntiForensics() {
	// Clear terminal history
	// Note: This is a placeholder - actual implementation would be more sophisticated
	color.Yellow("🧹 Anti-forensics mode: Minimal logging enabled")
}

// GenerateCoverTraffic creates legitimate-looking traffic
func GenerateCoverTraffic(target string, duration time.Duration) {
	color.Cyan("🎭 Generating cover traffic...")

	legitimateSites := []string{
		"https://www.google.com",
		"https://www.wikipedia.org",
		"https://www.github.com",
		"https://www.stackoverflow.com",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	end := time.Now().Add(duration)

	for time.Now().Before(end) {
		site := legitimateSites[randInt(len(legitimateSites))]
		client.Get(site)
		time.Sleep(time.Duration(5+randInt(15)) * time.Second)
	}
}
