package utils

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// BrowserFingerprint represents a complete browser fingerprint
type BrowserFingerprint struct {
	UserAgent       string
	AcceptLanguage  string
	AcceptEncoding  string
	Accept          string
	Platform        string
	Vendor          string
	Browser         string
	BrowserVersion  string
	OS              string
	OSVersion       string
	Mobile          bool
	SecChUA         string
	SecChUAMobile   string
	SecChUAPlatform string
	SecFetchDest    string
	SecFetchMode    string
	SecFetchSite    string
	Weight          float64
}

// FingerprintDatabase manages browser fingerprints with ML
type FingerprintDatabase struct {
	fingerprints      []*BrowserFingerprint
	fingerprintScores map[string]*FingerprintScore
	mutex             sync.RWMutex

	// ML tracking
	learningRate    float64
	explorationRate float64

	// Current fingerprint
	currentFingerprint *BrowserFingerprint

	// Usage history
	usageHistory map[string][]FingerprintResult
}

// FingerprintScore tracks ML metrics
type FingerprintScore struct {
	UserAgent     string
	SuccessRate   float64
	DetectionRate float64
	QValue        float64
	UsageCount    int64
	SuccessCount  int64
	BlockCount    int64
	LastUsed      time.Time

	resultHistory []bool
}

// FingerprintResult tracks usage outcome
type FingerprintResult struct {
	UserAgent  string
	Success    bool
	Blocked    bool
	Timestamp  time.Time
	TargetHost string
}

// NewFingerprintDatabase creates ML-powered fingerprint database
func NewFingerprintDatabase() *FingerprintDatabase {
	fd := &FingerprintDatabase{
		fingerprints:      make([]*BrowserFingerprint, 0),
		fingerprintScores: make(map[string]*FingerprintScore),
		learningRate:      0.15,
		explorationRate:   0.1,
		usageHistory:      make(map[string][]FingerprintResult),
	}

	fd.loadFingerprints()
	return fd
}

// loadFingerprints loads comprehensive browser fingerprint database
func (fd *FingerprintDatabase) loadFingerprints() {
	fingerprints := []*BrowserFingerprint{
		// Chrome 120 Windows 11
		{
			UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			Platform:        "Win32",
			Vendor:          "Google Inc.",
			Browser:         "Chrome",
			BrowserVersion:  "120.0.0.0",
			OS:              "Windows",
			OSVersion:       "10",
			Mobile:          false,
			SecChUA:         `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			SecChUAMobile:   "?0",
			SecChUAPlatform: `"Windows"`,
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          1.0,
		},

		// Chrome 120 macOS
		{
			UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			Platform:        "MacIntel",
			Vendor:          "Google Inc.",
			Browser:         "Chrome",
			BrowserVersion:  "120.0.0.0",
			OS:              "Mac OS X",
			OSVersion:       "10_15_7",
			Mobile:          false,
			SecChUA:         `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			SecChUAMobile:   "?0",
			SecChUAPlatform: `"macOS"`,
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          1.0,
		},

		// Firefox 121 Windows 11
		{
			UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			AcceptLanguage:  "en-US,en;q=0.5",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			Platform:        "Win32",
			Vendor:          "",
			Browser:         "Firefox",
			BrowserVersion:  "121.0",
			OS:              "Windows",
			OSVersion:       "10",
			Mobile:          false,
			SecChUA:         "",
			SecChUAMobile:   "",
			SecChUAPlatform: "",
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.9,
		},

		// Firefox 121 macOS
		{
			UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
			AcceptLanguage:  "en-US,en;q=0.5",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			Platform:        "MacIntel",
			Vendor:          "",
			Browser:         "Firefox",
			BrowserVersion:  "121.0",
			OS:              "Mac OS X",
			OSVersion:       "10.15",
			Mobile:          false,
			SecChUA:         "",
			SecChUAMobile:   "",
			SecChUAPlatform: "",
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.9,
		},

		// Safari 17.2 macOS
		{
			UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			Platform:        "MacIntel",
			Vendor:          "Apple Computer, Inc.",
			Browser:         "Safari",
			BrowserVersion:  "17.2",
			OS:              "Mac OS X",
			OSVersion:       "10_15_7",
			Mobile:          false,
			SecChUA:         "",
			SecChUAMobile:   "",
			SecChUAPlatform: "",
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.85,
		},

		// Edge 120 Windows 11
		{
			UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			Platform:        "Win32",
			Vendor:          "Google Inc.",
			Browser:         "Edge",
			BrowserVersion:  "120.0.0.0",
			OS:              "Windows",
			OSVersion:       "10",
			Mobile:          false,
			SecChUA:         `"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"`,
			SecChUAMobile:   "?0",
			SecChUAPlatform: `"Windows"`,
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.95,
		},

		// Chrome 119 Android
		{
			UserAgent:       "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			Platform:        "Linux armv81",
			Vendor:          "Google Inc.",
			Browser:         "Chrome",
			BrowserVersion:  "119.0.0.0",
			OS:              "Android",
			OSVersion:       "13",
			Mobile:          true,
			SecChUA:         `"Not_A Brand";v="8", "Chromium";v="119", "Google Chrome";v="119"`,
			SecChUAMobile:   "?1",
			SecChUAPlatform: `"Android"`,
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.92,
		},

		// Safari iOS 17.2
		{
			UserAgent:       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			Platform:        "iPhone",
			Vendor:          "Apple Computer, Inc.",
			Browser:         "Safari",
			BrowserVersion:  "17.2",
			OS:              "iOS",
			OSVersion:       "17_2",
			Mobile:          true,
			SecChUA:         "",
			SecChUAMobile:   "",
			SecChUAPlatform: "",
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.91,
		},

		// Chrome 120 Linux
		{
			UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			Platform:        "Linux x86_64",
			Vendor:          "Google Inc.",
			Browser:         "Chrome",
			BrowserVersion:  "120.0.0.0",
			OS:              "Linux",
			OSVersion:       "",
			Mobile:          false,
			SecChUA:         `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			SecChUAMobile:   "?0",
			SecChUAPlatform: `"Linux"`,
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.88,
		},

		// Firefox 121 Linux
		{
			UserAgent:       "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
			AcceptLanguage:  "en-US,en;q=0.5",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			Platform:        "Linux x86_64",
			Vendor:          "",
			Browser:         "Firefox",
			BrowserVersion:  "121.0",
			OS:              "Linux",
			OSVersion:       "",
			Mobile:          false,
			SecChUA:         "",
			SecChUAMobile:   "",
			SecChUAPlatform: "",
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.87,
		},

		// Opera 105 Windows
		{
			UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			Platform:        "Win32",
			Vendor:          "Google Inc.",
			Browser:         "Opera",
			BrowserVersion:  "105.0.0.0",
			OS:              "Windows",
			OSVersion:       "10",
			Mobile:          false,
			SecChUA:         `"Not_A Brand";v="8", "Chromium";v="119", "Opera";v="105"`,
			SecChUAMobile:   "?0",
			SecChUAPlatform: `"Windows"`,
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.75,
		},

		// Brave 1.61 Windows
		{
			UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
			Platform:        "Win32",
			Vendor:          "Google Inc.",
			Browser:         "Brave",
			BrowserVersion:  "1.61",
			OS:              "Windows",
			OSVersion:       "10",
			Mobile:          false,
			SecChUA:         `"Not_A Brand";v="8", "Chromium";v="120"`,
			SecChUAMobile:   "?0",
			SecChUAPlatform: `"Windows"`,
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.80,
		},

		// Vivaldi 6.5 macOS
		{
			UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.39",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			Platform:        "MacIntel",
			Vendor:          "Google Inc.",
			Browser:         "Vivaldi",
			BrowserVersion:  "6.5.3206.39",
			OS:              "Mac OS X",
			OSVersion:       "10_15_7",
			Mobile:          false,
			SecChUA:         `"Not_A Brand";v="8", "Chromium";v="120", "Vivaldi";v="6.5"`,
			SecChUAMobile:   "?0",
			SecChUAPlatform: `"macOS"`,
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.72,
		},

		// Samsung Internet 23.0 Android
		{
			UserAgent:       "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
			Platform:        "Linux armv81",
			Vendor:          "Google Inc.",
			Browser:         "Samsung Internet",
			BrowserVersion:  "23.0",
			OS:              "Android",
			OSVersion:       "13",
			Mobile:          true,
			SecChUA:         `"Samsung Internet";v="23", "Not_A Brand";v="8", "Chromium";v="115"`,
			SecChUAMobile:   "?1",
			SecChUAPlatform: `"Android"`,
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.78,
		},

		// Firefox Android 121
		{
			UserAgent:       "Mozilla/5.0 (Android 13; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
			AcceptLanguage:  "en-US,en;q=0.5",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			Platform:        "Linux armv81",
			Vendor:          "",
			Browser:         "Firefox",
			BrowserVersion:  "121.0",
			OS:              "Android",
			OSVersion:       "13",
			Mobile:          true,
			SecChUA:         "",
			SecChUAMobile:   "",
			SecChUAPlatform: "",
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.82,
		},

		// Chrome 119 iPad
		{
			UserAgent:       "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/119.0.6045.169 Mobile/15E148 Safari/604.1",
			AcceptLanguage:  "en-US,en;q=0.9",
			AcceptEncoding:  "gzip, deflate, br",
			Accept:          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
			Platform:        "iPad",
			Vendor:          "Apple Computer, Inc.",
			Browser:         "Chrome",
			BrowserVersion:  "119.0.6045.169",
			OS:              "iOS",
			OSVersion:       "17_2",
			Mobile:          true,
			SecChUA:         "",
			SecChUAMobile:   "",
			SecChUAPlatform: "",
			SecFetchDest:    "document",
			SecFetchMode:    "navigate",
			SecFetchSite:    "none",
			Weight:          0.84,
		},
	}

	fd.mutex.Lock()
	fd.fingerprints = fingerprints
	for _, fp := range fingerprints {
		fd.fingerprintScores[fp.UserAgent] = &FingerprintScore{
			UserAgent:     fp.UserAgent,
			SuccessRate:   0.5,
			resultHistory: make([]bool, 0, 100),
		}
	}
	fd.mutex.Unlock()
}

// SelectBestFingerprint uses ML to select optimal fingerprint
func (fd *FingerprintDatabase) SelectBestFingerprint() *BrowserFingerprint {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	type scored struct {
		fingerprint *BrowserFingerprint
		score       float64
	}

	var scoredList []scored

	for _, fp := range fd.fingerprints {
		score := fp.Weight

		if fs, exists := fd.fingerprintScores[fp.UserAgent]; exists {
			mlScore := fd.calculateScore(fs)
			score = 0.4*fp.Weight + 0.6*mlScore
		}

		// Epsilon-greedy exploration
		if rand.Float64() < fd.explorationRate {
			score += rand.Float64() * 0.3
		}

		scoredList = append(scoredList, scored{fingerprint: fp, score: score})
	}

	// Select best
	bestIdx := 0
	bestScore := scoredList[0].score
	for i, s := range scoredList {
		if s.score > bestScore {
			bestScore = s.score
			bestIdx = i
		}
	}

	fd.currentFingerprint = scoredList[bestIdx].fingerprint
	return scoredList[bestIdx].fingerprint
}

// calculateScore computes ML score
func (fd *FingerprintDatabase) calculateScore(fs *FingerprintScore) float64 {
	score := fs.SuccessRate * 0.6
	score -= fs.DetectionRate * 0.3

	// Recency bonus
	hoursSinceUse := time.Since(fs.LastUsed).Hours()
	recencyBonus := 1.0 / (1.0 + hoursSinceUse/24.0)
	score += recencyBonus * 0.1

	// Q-value
	if fs.QValue != 0 {
		score = 0.7*score + 0.3*fs.QValue
	}

	return score
}

// GetHeaders returns HTTP headers for fingerprint
func (fd *FingerprintDatabase) GetHeaders(fp *BrowserFingerprint) map[string]string {
	headers := make(map[string]string)

	headers["User-Agent"] = fp.UserAgent
	headers["Accept"] = fp.Accept
	headers["Accept-Language"] = fd.variateLanguage(fp.AcceptLanguage)
	headers["Accept-Encoding"] = fp.AcceptEncoding

	// Chromium-based headers
	if fp.SecChUA != "" {
		headers["sec-ch-ua"] = fp.SecChUA
		headers["sec-ch-ua-mobile"] = fp.SecChUAMobile
		headers["sec-ch-ua-platform"] = fp.SecChUAPlatform
	}

	// Sec-Fetch headers
	headers["Sec-Fetch-Dest"] = fp.SecFetchDest
	headers["Sec-Fetch-Mode"] = fp.SecFetchMode
	headers["Sec-Fetch-Site"] = fp.SecFetchSite
	headers["Sec-Fetch-User"] = "?1"

	// Common headers
	headers["Upgrade-Insecure-Requests"] = "1"
	headers["Cache-Control"] = "max-age=0"

	// DNT header (random)
	if rand.Float64() < 0.3 {
		headers["DNT"] = "1"
	}

	return headers
}

// GetHeadersForRequest returns headers for specific request type
func (fd *FingerprintDatabase) GetHeadersForRequest(fp *BrowserFingerprint, requestType string) map[string]string {
	headers := fd.GetHeaders(fp)

	switch requestType {
	case "xhr":
		headers["Sec-Fetch-Dest"] = "empty"
		headers["Sec-Fetch-Mode"] = "cors"
		headers["X-Requested-With"] = "XMLHttpRequest"
		delete(headers, "Upgrade-Insecure-Requests")

	case "fetch":
		headers["Sec-Fetch-Dest"] = "empty"
		headers["Sec-Fetch-Mode"] = "cors"
		delete(headers, "Upgrade-Insecure-Requests")

	case "image":
		headers["Sec-Fetch-Dest"] = "image"
		headers["Sec-Fetch-Mode"] = "no-cors"
		headers["Accept"] = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
		delete(headers, "Upgrade-Insecure-Requests")

	case "script":
		headers["Sec-Fetch-Dest"] = "script"
		headers["Sec-Fetch-Mode"] = "no-cors"
		delete(headers, "Upgrade-Insecure-Requests")

	case "stylesheet":
		headers["Sec-Fetch-Dest"] = "style"
		headers["Sec-Fetch-Mode"] = "no-cors"
		headers["Accept"] = "text/css,*/*;q=0.1"
		delete(headers, "Upgrade-Insecure-Requests")
	}

	return headers
}

// variateLanguage adds slight variation to Accept-Language
func (fd *FingerprintDatabase) variateLanguage(base string) string {
	languages := []string{
		"en-US,en;q=0.9",
		"en-US,en;q=0.9,es;q=0.8",
		"en-US,en;q=0.9,fr;q=0.8",
		"en-GB,en;q=0.9",
		"en-US,en;q=0.5",
	}

	// 70% use base, 30% use variation
	if rand.Float64() < 0.7 {
		return base
	}

	return languages[rand.Intn(len(languages))]
}

// GetMobileFingerprints returns mobile fingerprints
func (fd *FingerprintDatabase) GetMobileFingerprints() []*BrowserFingerprint {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	var mobile []*BrowserFingerprint
	for _, fp := range fd.fingerprints {
		if fp.Mobile {
			mobile = append(mobile, fp)
		}
	}
	return mobile
}

// GetDesktopFingerprints returns desktop fingerprints
func (fd *FingerprintDatabase) GetDesktopFingerprints() []*BrowserFingerprint {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	var desktop []*BrowserFingerprint
	for _, fp := range fd.fingerprints {
		if !fp.Mobile {
			desktop = append(desktop, fp)
		}
	}
	return desktop
}

// GetByBrowser returns fingerprints for specific browser
func (fd *FingerprintDatabase) GetByBrowser(browser string) []*BrowserFingerprint {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	var result []*BrowserFingerprint
	for _, fp := range fd.fingerprints {
		if strings.EqualFold(fp.Browser, browser) {
			result = append(result, fp)
		}
	}
	return result
}

// GetByOS returns fingerprints for specific OS
func (fd *FingerprintDatabase) GetByOS(os string) []*BrowserFingerprint {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	var result []*BrowserFingerprint
	for _, fp := range fd.fingerprints {
		if strings.Contains(strings.ToLower(fp.OS), strings.ToLower(os)) {
			result = append(result, fp)
		}
	}
	return result
}

// ReportResult updates ML model with usage result
func (fd *FingerprintDatabase) ReportResult(userAgent string, success bool, blocked bool, targetHost string) {
	fd.mutex.Lock()
	defer fd.mutex.Unlock()

	fs, exists := fd.fingerprintScores[userAgent]
	if !exists {
		return
	}

	fs.UsageCount++
	fs.LastUsed = time.Now()

	if success && !blocked {
		fs.SuccessCount++
	}
	if blocked {
		fs.BlockCount++
	}

	// Update result history
	fs.resultHistory = append(fs.resultHistory, success && !blocked)
	if len(fs.resultHistory) > 100 {
		fs.resultHistory = fs.resultHistory[1:]
	}

	successCount := 0
	for _, r := range fs.resultHistory {
		if r {
			successCount++
		}
	}
	fs.SuccessRate = float64(successCount) / float64(len(fs.resultHistory))

	// Detection rate
	if fs.UsageCount > 0 {
		fs.DetectionRate = float64(fs.BlockCount) / float64(fs.UsageCount)
	}

	// Q-Learning
	reward := -0.5
	if success && !blocked {
		reward = 1.0
	}
	if blocked {
		reward = -1.0
	}
	fs.QValue = fs.QValue + fd.learningRate*(reward-fs.QValue)

	// Store result
	result := FingerprintResult{
		UserAgent:  userAgent,
		Success:    success,
		Blocked:    blocked,
		Timestamp:  time.Now(),
		TargetHost: targetHost,
	}

	history := fd.usageHistory[userAgent]
	history = append(history, result)
	if len(history) > 500 {
		history = history[1:]
	}
	fd.usageHistory[userAgent] = history
}

// GetStats returns ML statistics
func (fd *FingerprintDatabase) GetStats() map[string]interface{} {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	fpStats := make([]map[string]interface{}, 0)

	for _, fs := range fd.fingerprintScores {
		if fs.UsageCount > 0 {
			// Find browser name from UA
			browser := "Unknown"
			for _, fp := range fd.fingerprints {
				if fp.UserAgent == fs.UserAgent {
					browser = fp.Browser
					break
				}
			}

			fpStats = append(fpStats, map[string]interface{}{
				"browser":        browser,
				"usage_count":    fs.UsageCount,
				"success_rate":   strings.TrimSpace(strings.Split(strings.TrimSpace(fmt.Sprintf("%.1f%%", fs.SuccessRate*100)), " ")[0]),
				"detection_rate": strings.TrimSpace(strings.Split(strings.TrimSpace(fmt.Sprintf("%.1f%%", fs.DetectionRate*100)), " ")[0]),
				"q_value":        strings.TrimSpace(strings.Split(strings.TrimSpace(fmt.Sprintf("%.3f", fs.QValue)), " ")[0]),
			})
		}
	}

	currentUA := ""
	if fd.currentFingerprint != nil {
		currentUA = fd.currentFingerprint.UserAgent
	}

	return map[string]interface{}{
		"total_fingerprints": len(fd.fingerprints),
		"learning_rate":      fd.learningRate,
		"exploration_rate":   fd.explorationRate,
		"current_ua":         currentUA,
		"fingerprint_stats":  fpStats,
	}
}

// GetCurrentFingerprint returns current fingerprint
func (fd *FingerprintDatabase) GetCurrentFingerprint() *BrowserFingerprint {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()
	return fd.currentFingerprint
}

// RandomFingerprint returns random fingerprint
func (fd *FingerprintDatabase) RandomFingerprint() *BrowserFingerprint {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	if len(fd.fingerprints) == 0 {
		return nil
	}

	fp := fd.fingerprints[rand.Intn(len(fd.fingerprints))]
	fd.currentFingerprint = fp
	return fp
}

// GetBestFingerprints returns top N performing fingerprints
func (fd *FingerprintDatabase) GetBestFingerprints(n int) []*BrowserFingerprint {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	type scored struct {
		fingerprint *BrowserFingerprint
		score       float64
	}

	var scoredList []scored

	for _, fp := range fd.fingerprints {
		score := 0.0
		if fs, exists := fd.fingerprintScores[fp.UserAgent]; exists {
			score = fd.calculateScore(fs)
		}
		scoredList = append(scoredList, scored{fingerprint: fp, score: score})
	}

	// Sort by score
	for i := 0; i < len(scoredList); i++ {
		for j := i + 1; j < len(scoredList); j++ {
			if scoredList[j].score > scoredList[i].score {
				scoredList[i], scoredList[j] = scoredList[j], scoredList[i]
			}
		}
	}

	if n > len(scoredList) {
		n = len(scoredList)
	}

	result := make([]*BrowserFingerprint, n)
	for i := 0; i < n; i++ {
		result[i] = scoredList[i].fingerprint
	}

	return result
}

// RotateFingerprint rotates to new fingerprint
func (fd *FingerprintDatabase) RotateFingerprint() *BrowserFingerprint {
	return fd.SelectBestFingerprint()
}

// GetFingerprintByUA returns fingerprint by user agent
func (fd *FingerprintDatabase) GetFingerprintByUA(userAgent string) *BrowserFingerprint {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	for _, fp := range fd.fingerprints {
		if fp.UserAgent == userAgent {
			return fp
		}
	}
	return nil
}

// ListBrowsers returns unique browser names
func (fd *FingerprintDatabase) ListBrowsers() []string {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	seen := make(map[string]bool)
	browsers := make([]string, 0)

	for _, fp := range fd.fingerprints {
		if !seen[fp.Browser] {
			seen[fp.Browser] = true
			browsers = append(browsers, fp.Browser)
		}
	}

	return browsers
}

// ListOS returns unique OS names
func (fd *FingerprintDatabase) ListOS() []string {
	fd.mutex.RLock()
	defer fd.mutex.RUnlock()

	seen := make(map[string]bool)
	oses := make([]string, 0)

	for _, fp := range fd.fingerprints {
		if !seen[fp.OS] {
			seen[fp.OS] = true
			oses = append(oses, fp.OS)
		}
	}

	return oses
}
