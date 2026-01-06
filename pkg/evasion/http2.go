package evasion

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HTTP2Profile represents HTTP/2 fingerprint characteristics
type HTTP2Profile struct {
	Name              string
	InitialSettings   []http2.Setting
	WindowUpdate      uint32
	HeaderTableSize   uint32
	PriorityFrames    bool
	PriorityWeights   []PrioritySpec
	PseudoHeaderOrder []string
	HeaderOrder       []string
	ConnectionPreface bool
	MaxFrameSize      uint32
	MaxHeaderListSize uint32
	EnablePush        bool
	GREASE            bool
	Weight            float64
}

// PrioritySpec represents stream priority
type PrioritySpec struct {
	StreamID  uint32
	Exclusive bool
	DependsOn uint32
	Weight    uint8
}

// HTTP2Randomizer handles ML-based HTTP/2 fingerprint variation
type HTTP2Randomizer struct {
	profiles      []*HTTP2Profile
	profileScores map[string]*HTTP2ProfileScore
	mutex         sync.RWMutex

	// ML parameters
	learningRate    float64
	explorationRate float64

	// Current profile
	currentProfile *HTTP2Profile

	// Usage tracking
	usageHistory map[string][]HTTP2Result
}

// HTTP2ProfileScore tracks ML metrics
type HTTP2ProfileScore struct {
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

// HTTP2Result tracks usage outcome
type HTTP2Result struct {
	ProfileName string
	Success     bool
	Latency     time.Duration
	Blocked     bool
	Timestamp   time.Time
	TargetHost  string
}

// NewHTTP2Randomizer creates ML-powered HTTP/2 fingerprint randomizer
func NewHTTP2Randomizer() *HTTP2Randomizer {
	hr := &HTTP2Randomizer{
		profiles:        make([]*HTTP2Profile, 0),
		profileScores:   make(map[string]*HTTP2ProfileScore),
		learningRate:    0.15,
		explorationRate: 0.1,
		usageHistory:    make(map[string][]HTTP2Result),
	}

	hr.loadHTTP2Profiles()
	return hr
}

// loadHTTP2Profiles loads real browser HTTP/2 fingerprints
func (hr *HTTP2Randomizer) loadHTTP2Profiles() {
	profiles := []*HTTP2Profile{
		// Chrome 120
		{
			Name: "Chrome_120",
			InitialSettings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingEnablePush, Val: 1},
				{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
				{ID: http2.SettingInitialWindowSize, Val: 6291456},
				{ID: http2.SettingMaxFrameSize, Val: 16384},
				{ID: http2.SettingMaxHeaderListSize, Val: 262144},
			},
			WindowUpdate:      15663105,
			HeaderTableSize:   65536,
			MaxFrameSize:      16384,
			MaxHeaderListSize: 262144,
			EnablePush:        true,
			PriorityFrames:    true,
			PriorityWeights: []PrioritySpec{
				{StreamID: 3, Exclusive: false, DependsOn: 0, Weight: 200},
				{StreamID: 5, Exclusive: false, DependsOn: 0, Weight: 100},
				{StreamID: 7, Exclusive: false, DependsOn: 0, Weight: 0},
				{StreamID: 9, Exclusive: false, DependsOn: 7, Weight: 0},
				{StreamID: 11, Exclusive: false, DependsOn: 3, Weight: 0},
			},
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
			HeaderOrder: []string{
				"user-agent", "accept", "accept-encoding",
				"accept-language", "cache-control", "upgrade-insecure-requests",
			},
			ConnectionPreface: true,
			GREASE:            true,
			Weight:            1.0,
		},

		// Firefox 121
		{
			Name: "Firefox_121",
			InitialSettings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingEnablePush, Val: 0},
				{ID: http2.SettingMaxConcurrentStreams, Val: 128},
				{ID: http2.SettingInitialWindowSize, Val: 131072},
				{ID: http2.SettingMaxFrameSize, Val: 16384},
			},
			WindowUpdate:      12517377,
			HeaderTableSize:   65536,
			MaxFrameSize:      16384,
			MaxHeaderListSize: 0,
			EnablePush:        false,
			PriorityFrames:    false,
			PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
			HeaderOrder: []string{
				"user-agent", "accept", "accept-language",
				"accept-encoding", "te", "upgrade-insecure-requests",
			},
			ConnectionPreface: true,
			GREASE:            false,
			Weight:            0.9,
		},

		// Safari 17
		{
			Name: "Safari_17",
			InitialSettings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 4096},
				{ID: http2.SettingEnablePush, Val: 0},
				{ID: http2.SettingMaxConcurrentStreams, Val: 100},
				{ID: http2.SettingInitialWindowSize, Val: 2097152},
				{ID: http2.SettingMaxFrameSize, Val: 16384},
			},
			WindowUpdate:      10485760,
			HeaderTableSize:   4096,
			MaxFrameSize:      16384,
			MaxHeaderListSize: 0,
			EnablePush:        false,
			PriorityFrames:    true,
			PriorityWeights: []PrioritySpec{
				{StreamID: 3, Exclusive: false, DependsOn: 0, Weight: 200},
				{StreamID: 5, Exclusive: false, DependsOn: 0, Weight: 100},
			},
			PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
			HeaderOrder: []string{
				"accept", "user-agent", "accept-language",
				"accept-encoding",
			},
			ConnectionPreface: true,
			GREASE:            false,
			Weight:            0.85,
		},

		// Edge 120
		{
			Name: "Edge_120",
			InitialSettings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingEnablePush, Val: 1},
				{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
				{ID: http2.SettingInitialWindowSize, Val: 6291456},
				{ID: http2.SettingMaxFrameSize, Val: 16384},
				{ID: http2.SettingMaxHeaderListSize, Val: 262144},
			},
			WindowUpdate:      15663105,
			HeaderTableSize:   65536,
			MaxFrameSize:      16384,
			MaxHeaderListSize: 262144,
			EnablePush:        true,
			PriorityFrames:    true,
			PriorityWeights: []PrioritySpec{
				{StreamID: 3, Exclusive: false, DependsOn: 0, Weight: 200},
				{StreamID: 5, Exclusive: false, DependsOn: 0, Weight: 100},
				{StreamID: 7, Exclusive: false, DependsOn: 0, Weight: 0},
			},
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
			HeaderOrder: []string{
				"user-agent", "accept", "accept-encoding",
				"accept-language", "upgrade-insecure-requests",
			},
			ConnectionPreface: true,
			GREASE:            true,
			Weight:            0.95,
		},

		// Chrome Android
		{
			Name: "Chrome_Android",
			InitialSettings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingEnablePush, Val: 1},
				{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
				{ID: http2.SettingInitialWindowSize, Val: 6291456},
				{ID: http2.SettingMaxFrameSize, Val: 16384},
				{ID: http2.SettingMaxHeaderListSize, Val: 262144},
			},
			WindowUpdate:      15663105,
			HeaderTableSize:   65536,
			MaxFrameSize:      16384,
			MaxHeaderListSize: 262144,
			EnablePush:        true,
			PriorityFrames:    true,
			PriorityWeights: []PrioritySpec{
				{StreamID: 3, Exclusive: false, DependsOn: 0, Weight: 200},
				{StreamID: 5, Exclusive: false, DependsOn: 0, Weight: 100},
			},
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
			HeaderOrder: []string{
				"user-agent", "accept", "accept-encoding",
				"accept-language",
			},
			ConnectionPreface: true,
			GREASE:            true,
			Weight:            0.92,
		},

		// Opera 105
		{
			Name: "Opera_105",
			InitialSettings: []http2.Setting{
				{ID: http2.SettingHeaderTableSize, Val: 65536},
				{ID: http2.SettingEnablePush, Val: 1},
				{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
				{ID: http2.SettingInitialWindowSize, Val: 6291456},
				{ID: http2.SettingMaxFrameSize, Val: 16384},
			},
			WindowUpdate:      15663105,
			HeaderTableSize:   65536,
			MaxFrameSize:      16384,
			MaxHeaderListSize: 0,
			EnablePush:        true,
			PriorityFrames:    true,
			PriorityWeights: []PrioritySpec{
				{StreamID: 3, Exclusive: false, DependsOn: 0, Weight: 200},
			},
			PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
			HeaderOrder: []string{
				"user-agent", "accept", "accept-encoding",
				"accept-language",
			},
			ConnectionPreface: true,
			GREASE:            true,
			Weight:            0.75,
		},
	}

	hr.mutex.Lock()
	hr.profiles = profiles
	for _, profile := range profiles {
		hr.profileScores[profile.Name] = &HTTP2ProfileScore{
			ProfileName:    profile.Name,
			SuccessRate:    0.5,
			latencyHistory: make([]time.Duration, 0, 100),
			resultHistory:  make([]bool, 0, 100),
		}
	}
	hr.mutex.Unlock()
}

// SelectBestProfile uses ML to select optimal profile
func (hr *HTTP2Randomizer) SelectBestProfile() *HTTP2Profile {
	hr.mutex.RLock()
	defer hr.mutex.RUnlock()

	type scored struct {
		profile *HTTP2Profile
		score   float64
	}

	var scoredList []scored

	for _, profile := range hr.profiles {
		score := profile.Weight

		if ps, exists := hr.profileScores[profile.Name]; exists {
			mlScore := hr.calculateProfileScore(ps)
			score = 0.4*profile.Weight + 0.6*mlScore
		}

		// Epsilon-greedy exploration
		if mrand.Float64() < hr.explorationRate {
			score += mrand.Float64() * 0.3
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

	hr.currentProfile = scoredList[bestIdx].profile
	return scoredList[bestIdx].profile
}

// calculateProfileScore computes ML score
func (hr *HTTP2Randomizer) calculateProfileScore(ps *HTTP2ProfileScore) float64 {
	score := ps.SuccessRate * 0.6
	score -= ps.DetectionRate * 0.3

	// Recency bonus
	hoursSinceUse := time.Since(ps.LastUsed).Hours()
	recencyBonus := 1.0 / (1.0 + hoursSinceUse/24.0)
	score += recencyBonus * 0.1

	// Q-value
	if ps.QValue != 0 {
		score = 0.7*score + 0.3*ps.QValue
	}

	return score
}

// BuildHTTP2Transport creates http2.Transport with profile
func (hr *HTTP2Randomizer) BuildHTTP2Transport() *http2.Transport {
	profile := hr.SelectBestProfile()

	transport := &http2.Transport{
		AllowHTTP:                  false,
		StrictMaxConcurrentStreams: false,
	}

	// Apply settings via connection preface
	hr.currentProfile = profile

	return transport
}

// GetConnectionPreface generates HTTP/2 connection preface with settings
func (hr *HTTP2Randomizer) GetConnectionPreface() []byte {
	if hr.currentProfile == nil {
		hr.SelectBestProfile()
	}

	var buf bytes.Buffer

	// Write preface
	buf.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

	// Write SETTINGS frame
	hr.writeSettingsFrame(&buf, hr.currentProfile.InitialSettings)

	// Write WINDOW_UPDATE frame
	if hr.currentProfile.WindowUpdate > 0 {
		hr.writeWindowUpdateFrame(&buf, 0, hr.currentProfile.WindowUpdate)
	}

	// Write PRIORITY frames
	if hr.currentProfile.PriorityFrames {
		for _, priority := range hr.currentProfile.PriorityWeights {
			hr.writePriorityFrame(&buf, priority)
		}
	}

	return buf.Bytes()
}

// writeSettingsFrame writes HTTP/2 SETTINGS frame
func (hr *HTTP2Randomizer) writeSettingsFrame(buf *bytes.Buffer, settings []http2.Setting) {
	frameHeader := make([]byte, 9)

	payload := make([]byte, len(settings)*6)
	for i, setting := range settings {
		binary.BigEndian.PutUint16(payload[i*6:], uint16(setting.ID))
		binary.BigEndian.PutUint32(payload[i*6+2:], setting.Val)
	}

	// Frame header
	length := len(payload)
	frameHeader[0] = byte(length >> 16)
	frameHeader[1] = byte(length >> 8)
	frameHeader[2] = byte(length)
	frameHeader[3] = 0x04 // SETTINGS frame type
	frameHeader[4] = 0x00 // No flags
	// Stream ID = 0 (already zero)

	buf.Write(frameHeader)
	buf.Write(payload)
}

// writeWindowUpdateFrame writes WINDOW_UPDATE frame
func (hr *HTTP2Randomizer) writeWindowUpdateFrame(buf *bytes.Buffer, streamID uint32, increment uint32) {
	frameHeader := make([]byte, 9)
	payload := make([]byte, 4)

	binary.BigEndian.PutUint32(payload, increment)

	// Frame header
	frameHeader[0] = 0x00
	frameHeader[1] = 0x00
	frameHeader[2] = 0x04 // Length = 4
	frameHeader[3] = 0x08 // WINDOW_UPDATE frame type
	frameHeader[4] = 0x00 // No flags
	binary.BigEndian.PutUint32(frameHeader[5:], streamID)

	buf.Write(frameHeader)
	buf.Write(payload)
}

// writePriorityFrame writes PRIORITY frame
func (hr *HTTP2Randomizer) writePriorityFrame(buf *bytes.Buffer, priority PrioritySpec) {
	frameHeader := make([]byte, 9)
	payload := make([]byte, 5)

	// Stream dependency
	dependsOn := priority.DependsOn
	if priority.Exclusive {
		dependsOn |= 0x80000000
	}
	binary.BigEndian.PutUint32(payload, dependsOn)

	// Weight
	payload[4] = priority.Weight

	// Frame header
	frameHeader[0] = 0x00
	frameHeader[1] = 0x00
	frameHeader[2] = 0x05 // Length = 5
	frameHeader[3] = 0x02 // PRIORITY frame type
	frameHeader[4] = 0x00 // No flags
	binary.BigEndian.PutUint32(frameHeader[5:], priority.StreamID)

	buf.Write(frameHeader)
	buf.Write(payload)
}

// EncodeHeaders encodes HTTP headers with profile's ordering
func (hr *HTTP2Randomizer) EncodeHeaders(headers map[string]string) []byte {
	if hr.currentProfile == nil {
		hr.SelectBestProfile()
	}

	var buf bytes.Buffer
	encoder := hpack.NewEncoder(&buf)

	// Encode pseudo-headers first
	for _, name := range hr.currentProfile.PseudoHeaderOrder {
		if value, exists := headers[name]; exists {
			encoder.WriteField(hpack.HeaderField{Name: name, Value: value})
		}
	}

	// Encode regular headers in profile order
	for _, name := range hr.currentProfile.HeaderOrder {
		if value, exists := headers[name]; exists {
			encoder.WriteField(hpack.HeaderField{Name: name, Value: value})
		}
	}

	// Encode remaining headers
	for name, value := range headers {
		isInOrder := false
		for _, orderName := range hr.currentProfile.PseudoHeaderOrder {
			if name == orderName {
				isInOrder = true
				break
			}
		}
		if !isInOrder {
			for _, orderName := range hr.currentProfile.HeaderOrder {
				if name == orderName {
					isInOrder = true
					break
				}
			}
		}

		if !isInOrder {
			encoder.WriteField(hpack.HeaderField{Name: name, Value: value})
		}
	}

	return buf.Bytes()
}

// GetPseudoHeaderOrder returns pseudo-header order for current profile
func (hr *HTTP2Randomizer) GetPseudoHeaderOrder() []string {
	if hr.currentProfile == nil {
		hr.SelectBestProfile()
	}
	return hr.currentProfile.PseudoHeaderOrder
}

// GetHeaderOrder returns header order for current profile
func (hr *HTTP2Randomizer) GetHeaderOrder() []string {
	if hr.currentProfile == nil {
		hr.SelectBestProfile()
	}
	return hr.currentProfile.HeaderOrder
}

// GenerateStreamID generates realistic stream ID
func (hr *HTTP2Randomizer) GenerateStreamID(baseID uint32) uint32 {
	// HTTP/2 client streams are odd numbers
	return baseID*2 + 1
}

// GenerateGREASE generates GREASE frame if profile supports it
func (hr *HTTP2Randomizer) GenerateGREASE() []byte {
	if hr.currentProfile == nil || !hr.currentProfile.GREASE {
		return nil
	}

	greaseTypes := []byte{0x0b, 0x0f}
	greaseType := greaseTypes[mrand.Intn(len(greaseTypes))]

	var buf bytes.Buffer
	frameHeader := make([]byte, 9)

	// Random payload (1-8 bytes)
	payloadLen := mrand.Intn(8) + 1
	payload := make([]byte, payloadLen)
	rand.Read(payload)

	// Frame header
	frameHeader[0] = 0x00
	frameHeader[1] = 0x00
	frameHeader[2] = byte(payloadLen)
	frameHeader[3] = greaseType
	frameHeader[4] = 0x00

	buf.Write(frameHeader)
	buf.Write(payload)

	return buf.Bytes()
}

// ReportResult updates ML model with usage result
func (hr *HTTP2Randomizer) ReportResult(success bool, latency time.Duration, blocked bool, targetHost string) {
	hr.mutex.Lock()
	defer hr.mutex.Unlock()

	if hr.currentProfile == nil {
		return
	}

	profileName := hr.currentProfile.Name
	ps := hr.profileScores[profileName]

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

	// Detection rate
	if ps.UsageCount > 0 {
		ps.DetectionRate = float64(ps.BlockCount) / float64(ps.UsageCount)
	}

	// Q-Learning
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
	ps.QValue = ps.QValue + hr.learningRate*(reward-ps.QValue)

	// Store result
	result := HTTP2Result{
		ProfileName: profileName,
		Success:     success,
		Latency:     latency,
		Blocked:     blocked,
		Timestamp:   time.Now(),
		TargetHost:  targetHost,
	}

	history := hr.usageHistory[profileName]
	history = append(history, result)
	if len(history) > 500 {
		history = history[1:]
	}
	hr.usageHistory[profileName] = history
}

// GetCurrentProfile returns current profile
func (hr *HTTP2Randomizer) GetCurrentProfile() *HTTP2Profile {
	hr.mutex.RLock()
	defer hr.mutex.RUnlock()
	return hr.currentProfile
}

// GetStats returns ML statistics
func (hr *HTTP2Randomizer) GetStats() map[string]interface{} {
	hr.mutex.RLock()
	defer hr.mutex.RUnlock()

	profileStats := make([]map[string]interface{}, 0)

	for _, ps := range hr.profileScores {
		if ps.UsageCount > 0 {
			profileStats = append(profileStats, map[string]interface{}{
				"name":           ps.ProfileName,
				"usage_count":    ps.UsageCount,
				"success_rate":   fmt.Sprintf("%.1f%%", ps.SuccessRate*100),
				"detection_rate": fmt.Sprintf("%.1f%%", ps.DetectionRate*100),
				"avg_latency":    ps.AvgLatency.String(),
				"q_value":        fmt.Sprintf("%.3f", ps.QValue),
			})
		}
	}

	currentName := ""
	if hr.currentProfile != nil {
		currentName = hr.currentProfile.Name
	}

	return map[string]interface{}{
		"total_profiles":   len(hr.profiles),
		"learning_rate":    hr.learningRate,
		"exploration_rate": hr.explorationRate,
		"current_profile":  currentName,
		"profile_stats":    profileStats,
	}
}

// GetProfileByName returns specific profile
func (hr *HTTP2Randomizer) GetProfileByName(name string) *HTTP2Profile {
	hr.mutex.RLock()
	defer hr.mutex.RUnlock()

	for _, profile := range hr.profiles {
		if profile.Name == name {
			return profile
		}
	}

	return nil
}

// ListProfiles returns all profile names
func (hr *HTTP2Randomizer) ListProfiles() []string {
	hr.mutex.RLock()
	defer hr.mutex.RUnlock()

	names := make([]string, len(hr.profiles))
	for i, profile := range hr.profiles {
		names[i] = profile.Name
	}

	return names
}

// VariateSettings adds random variation to settings
func (hr *HTTP2Randomizer) VariateSettings(profile *HTTP2Profile) *HTTP2Profile {
	variated := *profile
	variated.InitialSettings = make([]http2.Setting, len(profile.InitialSettings))
	copy(variated.InitialSettings, profile.InitialSettings)

	// Slightly vary window size (±10%)
	for i := range variated.InitialSettings {
		if variated.InitialSettings[i].ID == http2.SettingInitialWindowSize {
			variation := float64(variated.InitialSettings[i].Val) * 0.1
			delta := int32(mrand.Float64()*variation) - int32(variation/2)
			newVal := int32(variated.InitialSettings[i].Val) + delta
			if newVal > 0 {
				variated.InitialSettings[i].Val = uint32(newVal)
			}
		}
	}

	// Vary window update (±5%)
	if variated.WindowUpdate > 0 {
		variation := float64(variated.WindowUpdate) * 0.05
		delta := int32(mrand.Float64()*variation) - int32(variation/2)
		newVal := int32(variated.WindowUpdate) + delta
		if newVal > 0 {
			variated.WindowUpdate = uint32(newVal)
		}
	}

	return &variated
}

// AdaptiveWindowSize calculates optimal window size based on latency
func (hr *HTTP2Randomizer) AdaptiveWindowSize(baseLatency time.Duration) uint32 {
	// Higher latency = larger window for better throughput
	latencyMs := baseLatency.Milliseconds()

	if latencyMs < 50 {
		return 1 << 20 // 1MB
	} else if latencyMs < 100 {
		return 2 << 20 // 2MB
	} else if latencyMs < 200 {
		return 4 << 20 // 4MB
	} else {
		return 6 << 20 // 6MB
	}
}

// GetBestProfiles returns top N performing profiles
func (hr *HTTP2Randomizer) GetBestProfiles(n int) []*HTTP2Profile {
	hr.mutex.RLock()
	defer hr.mutex.RUnlock()

	type scored struct {
		profile *HTTP2Profile
		score   float64
	}

	var scoredList []scored

	for _, profile := range hr.profiles {
		score := 0.0
		if ps, exists := hr.profileScores[profile.Name]; exists {
			score = hr.calculateProfileScore(ps)
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

	result := make([]*HTTP2Profile, n)
	for i := 0; i < n; i++ {
		result[i] = scoredList[i].profile
	}

	return result
}

// CalculateOptimalConcurrency determines best concurrent stream count
func (hr *HTTP2Randomizer) CalculateOptimalConcurrency(avgLatency time.Duration, successRate float64) uint32 {
	base := uint32(100)

	// Lower concurrency for high latency
	if avgLatency > 500*time.Millisecond {
		base = 50
	}

	// Lower concurrency for low success rate
	if successRate < 0.7 {
		base = uint32(math.Max(10, float64(base)*successRate))
	}

	return base
}

// ShouldUsePriorityFrames determines if priority frames should be used
func (hr *HTTP2Randomizer) ShouldUsePriorityFrames() bool {
	if hr.currentProfile != nil {
		return hr.currentProfile.PriorityFrames
	}
	return false
}

// GetOptimalFrameSize returns optimal frame size for current conditions
func (hr *HTTP2Randomizer) GetOptimalFrameSize(bandwidth float64) uint32 {
	// bandwidth in bytes/sec
	if bandwidth < 100*1024 { // < 100KB/s
		return 8192
	} else if bandwidth < 1024*1024 { // < 1MB/s
		return 16384
	} else {
		return 32768
	}
}
