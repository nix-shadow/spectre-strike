package evasion

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// BrowserProfile represents a browser fingerprint profile
type BrowserProfile struct {
	Name            string
	UserAgent       string
	TLSVersion      uint16
	CipherSuites    []uint16
	Curves          []tls.CurveID
	Extensions      []uint16
	ALPN            []string
	SignatureAlgs   []tls.SignatureScheme
	SupportedProtos []string
	MinVersion      uint16
	MaxVersion      uint16
	SessionTicket   bool
	GREASE          bool
	JA3String       string
	Weight          float64 // ML popularity weight
}

// JA3Randomizer handles ML-based TLS fingerprint randomization
type JA3Randomizer struct {
	profiles      []*BrowserProfile
	profileScores map[string]*ProfileScore
	mutex         sync.RWMutex

	// ML parameters
	learningRate    float64
	explorationRate float64

	// Usage statistics
	usageHistory map[string][]UsageResult

	// Current profile
	currentProfile *BrowserProfile
}

// ProfileScore tracks ML metrics for each profile
type ProfileScore struct {
	ProfileName   string
	SuccessRate   float64
	AvgLatency    time.Duration
	DetectionRate float64
	QValue        float64
	UsageCount    int64
	SuccessCount  int64
	BlockCount    int64
	LastUsed      time.Time

	latencyHistory []time.Duration
	resultHistory  []bool
}

// UsageResult tracks outcome of using a profile
type UsageResult struct {
	ProfileName string
	Success     bool
	Latency     time.Duration
	Blocked     bool
	Timestamp   time.Time
	TargetHost  string
}

// NewJA3Randomizer creates ML-powered JA3 randomizer
func NewJA3Randomizer() *JA3Randomizer {
	jr := &JA3Randomizer{
		profiles:        make([]*BrowserProfile, 0),
		profileScores:   make(map[string]*ProfileScore),
		learningRate:    0.15,
		explorationRate: 0.12,
		usageHistory:    make(map[string][]UsageResult),
	}

	jr.loadBrowserProfiles()
	return jr
}

// loadBrowserProfiles loads real browser TLS fingerprints
func (jr *JA3Randomizer) loadBrowserProfiles() {
	profiles := []*BrowserProfile{
		// Chrome 120 (Windows 11)
		{
			Name:       "Chrome_120_Win11",
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
				0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
				0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        true,
			Weight:        1.0,
		},

		// Firefox 121 (Windows 11)
		{
			Name:       "Firefox_121_Win11",
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
				0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009,
				0xc013, 0xc00a, 0xc014, 0x009c, 0x009d,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        false,
			Weight:        0.9,
		},

		// Chrome 120 (macOS)
		{
			Name:       "Chrome_120_macOS",
			UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
				0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
				0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        true,
			Weight:        1.0,
		},

		// Safari 17.2 (macOS)
		{
			Name:       "Safari_17_macOS",
			UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02c, 0xc030,
				0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b,
				0xc02f, 0x009e, 0xc024, 0xc028, 0x006b,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithP521AndSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        false,
			Weight:        0.85,
		},

		// Edge 120 (Windows 11)
		{
			Name:       "Edge_120_Win11",
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
				0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
				0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        true,
			Weight:        0.95,
		},

		// Chrome 120 (Linux)
		{
			Name:       "Chrome_120_Linux",
			UserAgent:  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
				0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
				0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        true,
			Weight:        0.88,
		},

		// Firefox 121 (Linux)
		{
			Name:       "Firefox_121_Linux",
			UserAgent:  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
				0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009,
				0xc013, 0xc00a, 0xc014, 0x009c, 0x009d,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        false,
			Weight:        0.87,
		},

		// Chrome 119 (Android)
		{
			Name:       "Chrome_119_Android",
			UserAgent:  "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
				0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
				0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        true,
			Weight:        0.92,
		},

		// Safari 17 (iOS)
		{
			Name:       "Safari_17_iOS",
			UserAgent:  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02c, 0xc030,
				0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b,
				0xc02f, 0x009e, 0xc024, 0xc028, 0x006b,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithP521AndSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        false,
			Weight:        0.91,
		},

		// Opera 105 (Windows)
		{
			Name:       "Opera_105_Win11",
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
			TLSVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
				0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
				0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
			},
			Curves: []tls.CurveID{
				tls.X25519, tls.CurveP256, tls.CurveP384,
			},
			SignatureAlgs: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			},
			ALPN:          []string{"h2", "http/1.1"},
			SessionTicket: true,
			GREASE:        true,
			Weight:        0.75,
		},
	}

	jr.mutex.Lock()
	jr.profiles = profiles
	for _, profile := range profiles {
		jr.profileScores[profile.Name] = &ProfileScore{
			ProfileName:    profile.Name,
			SuccessRate:    0.5,
			latencyHistory: make([]time.Duration, 0, 100),
			resultHistory:  make([]bool, 0, 100),
		}
	}
	jr.mutex.Unlock()
}

// GetTLSConfig returns TLS config with ML-selected profile
func (jr *JA3Randomizer) GetTLSConfig() *tls.Config {
	profile := jr.SelectBestProfile()
	return jr.buildTLSConfig(profile)
}

// GetTLSConfigForTarget returns optimized config for specific target
func (jr *JA3Randomizer) GetTLSConfigForTarget(targetHost string) *tls.Config {
	profile := jr.SelectProfileForTarget(targetHost)
	return jr.buildTLSConfig(profile)
}

// SelectBestProfile uses ML to select optimal profile
func (jr *JA3Randomizer) SelectBestProfile() *BrowserProfile {
	jr.mutex.RLock()
	defer jr.mutex.RUnlock()

	type scored struct {
		profile *BrowserProfile
		score   float64
	}

	var scoredList []scored

	for _, profile := range jr.profiles {
		score := profile.Weight

		if ps, exists := jr.profileScores[profile.Name]; exists {
			mlScore := jr.calculateProfileScore(ps)
			score = 0.4*profile.Weight + 0.6*mlScore
		}

		// Epsilon-greedy exploration
		if rand.Float64() < jr.explorationRate {
			score += rand.Float64() * 0.3
		}

		scoredList = append(scoredList, scored{profile: profile, score: score})
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

	jr.currentProfile = scoredList[bestIdx].profile
	return scoredList[bestIdx].profile
}

// SelectProfileForTarget selects profile based on target history
func (jr *JA3Randomizer) SelectProfileForTarget(targetHost string) *BrowserProfile {
	jr.mutex.RLock()
	defer jr.mutex.RUnlock()

	// Check history for this target
	bestProfile := jr.profiles[0]
	bestScore := 0.0

	for _, profile := range jr.profiles {
		score := profile.Weight * 0.4

		// Check usage history for this target
		if history, exists := jr.usageHistory[profile.Name]; exists {
			successOnTarget := 0
			totalOnTarget := 0

			for _, result := range history {
				if result.TargetHost == targetHost {
					totalOnTarget++
					if result.Success && !result.Blocked {
						successOnTarget++
					}
				}
			}

			if totalOnTarget > 0 {
				targetSuccessRate := float64(successOnTarget) / float64(totalOnTarget)
				score += targetSuccessRate * 0.6
			} else {
				// No history, use general score
				if ps, exists := jr.profileScores[profile.Name]; exists {
					score += ps.SuccessRate * 0.6
				}
			}
		}

		if score > bestScore {
			bestScore = score
			bestProfile = profile
		}
	}

	jr.currentProfile = bestProfile
	return bestProfile
}

// calculateProfileScore computes ML score for profile
func (jr *JA3Randomizer) calculateProfileScore(ps *ProfileScore) float64 {
	score := ps.SuccessRate * 0.5

	// Detection rate penalty
	score -= ps.DetectionRate * 0.3

	// Recency bonus
	hoursSinceUse := time.Since(ps.LastUsed).Hours()
	recencyBonus := 1.0 / (1.0 + hoursSinceUse/24.0)
	score += recencyBonus * 0.1

	// Q-value influence
	if ps.QValue != 0 {
		score = 0.7*score + 0.3*ps.QValue
	}

	return score
}

// buildTLSConfig constructs tls.Config from profile
func (jr *JA3Randomizer) buildTLSConfig(profile *BrowserProfile) *tls.Config {
	config := &tls.Config{
		MinVersion:         profile.MinVersion,
		MaxVersion:         profile.MaxVersion,
		CipherSuites:       make([]uint16, len(profile.CipherSuites)),
		CurvePreferences:   make([]tls.CurveID, len(profile.Curves)),
		InsecureSkipVerify: true,
		NextProtos:         profile.ALPN,
	}

	copy(config.CipherSuites, profile.CipherSuites)
	copy(config.CurvePreferences, profile.Curves)

	// Add GREASE if supported
	if profile.GREASE {
		config.CipherSuites = jr.addGREASE(config.CipherSuites)
	}

	// Session ticket
	if profile.SessionTicket {
		config.SessionTicketsDisabled = false
	} else {
		config.SessionTicketsDisabled = true
	}

	return config
}

// addGREASE adds GREASE values to cipher suites
func (jr *JA3Randomizer) addGREASE(suites []uint16) []uint16 {
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}

	grease := greaseValues[rand.Intn(len(greaseValues))]
	result := make([]uint16, 0, len(suites)+1)
	result = append(result, grease)
	result = append(result, suites...)

	return result
}

// ReportResult updates ML model with usage result
func (jr *JA3Randomizer) ReportResult(success bool, latency time.Duration, blocked bool, targetHost string) {
	jr.mutex.Lock()
	defer jr.mutex.Unlock()

	if jr.currentProfile == nil {
		return
	}

	profileName := jr.currentProfile.Name

	// Update profile score
	ps := jr.profileScores[profileName]
	ps.UsageCount++
	ps.LastUsed = time.Now()

	if success && !blocked {
		ps.SuccessCount++
	}
	if blocked {
		ps.BlockCount++
	}

	// Update latency
	ps.latencyHistory = append(ps.latencyHistory, latency)
	if len(ps.latencyHistory) > 100 {
		ps.latencyHistory = ps.latencyHistory[1:]
	}

	var sumLatency time.Duration
	for _, l := range ps.latencyHistory {
		sumLatency += l
	}
	ps.AvgLatency = sumLatency / time.Duration(len(ps.latencyHistory))

	// Update result history
	ps.resultHistory = append(ps.resultHistory, success && !blocked)
	if len(ps.resultHistory) > 100 {
		ps.resultHistory = ps.resultHistory[1:]
	}

	successCount := 0
	for _, r := range ps.resultHistory {
		if r {
			successCount++
		}
	}
	ps.SuccessRate = float64(successCount) / float64(len(ps.resultHistory))

	// Update detection rate
	if ps.UsageCount > 0 {
		ps.DetectionRate = float64(ps.BlockCount) / float64(ps.UsageCount)
	}

	// Q-Learning update
	reward := -0.5
	if success && !blocked {
		reward = 1.0
		if latency < 2*time.Second {
			reward += 0.2
		}
	}
	if blocked {
		reward = -1.0
	}
	ps.QValue = ps.QValue + jr.learningRate*(reward-ps.QValue)

	// Store usage result
	result := UsageResult{
		ProfileName: profileName,
		Success:     success,
		Latency:     latency,
		Blocked:     blocked,
		Timestamp:   time.Now(),
		TargetHost:  targetHost,
	}

	history := jr.usageHistory[profileName]
	history = append(history, result)
	if len(history) > 500 {
		history = history[1:]
	}
	jr.usageHistory[profileName] = history
}

// GetCurrentProfile returns the currently selected profile
func (jr *JA3Randomizer) GetCurrentProfile() *BrowserProfile {
	jr.mutex.RLock()
	defer jr.mutex.RUnlock()
	return jr.currentProfile
}

// GetStats returns ML statistics
func (jr *JA3Randomizer) GetStats() map[string]interface{} {
	jr.mutex.RLock()
	defer jr.mutex.RUnlock()

	profileStats := make([]map[string]interface{}, 0)

	for _, ps := range jr.profileScores {
		if ps.UsageCount > 0 {
			profileStats = append(profileStats, map[string]interface{}{
				"name":           ps.ProfileName,
				"usage_count":    ps.UsageCount,
				"success_rate":   fmt.Sprintf("%.1f%%", ps.SuccessRate*100),
				"detection_rate": fmt.Sprintf("%.1f%%", ps.DetectionRate*100),
				"avg_latency":    ps.AvgLatency.String(),
				"q_value":        fmt.Sprintf("%.3f", ps.QValue),
				"last_used":      ps.LastUsed.Format(time.RFC3339),
			})
		}
	}

	return map[string]interface{}{
		"total_profiles":   len(jr.profiles),
		"learning_rate":    jr.learningRate,
		"exploration_rate": jr.explorationRate,
		"current_profile":  jr.currentProfile.Name,
		"profile_stats":    profileStats,
	}
}

// GetProfileByName returns a specific profile
func (jr *JA3Randomizer) GetProfileByName(name string) *BrowserProfile {
	jr.mutex.RLock()
	defer jr.mutex.RUnlock()

	for _, profile := range jr.profiles {
		if profile.Name == name {
			return profile
		}
	}

	return nil
}

// ListProfiles returns all available profiles
func (jr *JA3Randomizer) ListProfiles() []string {
	jr.mutex.RLock()
	defer jr.mutex.RUnlock()

	names := make([]string, len(jr.profiles))
	for i, profile := range jr.profiles {
		names[i] = profile.Name
	}

	return names
}

// GetBestProfiles returns top N performing profiles
func (jr *JA3Randomizer) GetBestProfiles(n int) []*BrowserProfile {
	jr.mutex.RLock()
	defer jr.mutex.RUnlock()

	type scored struct {
		profile *BrowserProfile
		score   float64
	}

	var scoredList []scored

	for _, profile := range jr.profiles {
		score := 0.0
		if ps, exists := jr.profileScores[profile.Name]; exists {
			score = jr.calculateProfileScore(ps)
		}
		scoredList = append(scoredList, scored{profile: profile, score: score})
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

	result := make([]*BrowserProfile, n)
	for i := 0; i < n; i++ {
		result[i] = scoredList[i].profile
	}

	return result
}
