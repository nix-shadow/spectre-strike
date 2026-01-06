package evasion

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// TCPProfile represents TCP/IP stack fingerprint characteristics
type TCPProfile struct {
	Name            string
	TTL             int
	WindowSize      int
	WindowScale     int
	MSS             int
	SACKPermitted   bool
	Timestamps      bool
	NoDelay         bool
	KeepAlive       bool
	KeepAliveTime   int
	KeepAliveProbes int
	KeepAliveIntvl  int
	TCPOptions      []TCPOption
	IPTos           int
	IPFlags         int
	FragmentOffset  int
	Weight          float64
}

// TCPOption represents a TCP option
type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// TCPRandomizer handles ML-based TCP/IP stack fingerprint evasion
type TCPRandomizer struct {
	profiles      []*TCPProfile
	profileScores map[string]*TCPProfileScore
	mutex         sync.RWMutex

	// ML parameters
	learningRate    float64
	explorationRate float64

	// Current profile
	currentProfile *TCPProfile

	// Usage tracking
	usageHistory map[string][]TCPResult
}

// TCPProfileScore tracks ML metrics
type TCPProfileScore struct {
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

// TCPResult tracks usage outcome
type TCPResult struct {
	ProfileName string
	Success     bool
	Latency     time.Duration
	Blocked     bool
	Timestamp   time.Time
	TargetHost  string
}

// NewTCPRandomizer creates ML-powered TCP fingerprint randomizer
func NewTCPRandomizer() *TCPRandomizer {
	tr := &TCPRandomizer{
		profiles:        make([]*TCPProfile, 0),
		profileScores:   make(map[string]*TCPProfileScore),
		learningRate:    0.15,
		explorationRate: 0.1,
		usageHistory:    make(map[string][]TCPResult),
	}

	tr.loadTCPProfiles()
	return tr
}

// loadTCPProfiles loads real OS TCP/IP stack fingerprints
func (tr *TCPRandomizer) loadTCPProfiles() {
	profiles := []*TCPProfile{
		// Windows 11
		{
			Name:            "Windows_11",
			TTL:             128,
			WindowSize:      65535,
			WindowScale:     8,
			MSS:             1460,
			SACKPermitted:   true,
			Timestamps:      true,
			NoDelay:         true,
			KeepAlive:       true,
			KeepAliveTime:   7200,
			KeepAliveProbes: 10,
			KeepAliveIntvl:  1,
			TCPOptions: []TCPOption{
				{Kind: 2, Length: 4},  // MSS
				{Kind: 1, Length: 1},  // NOP
				{Kind: 3, Length: 3},  // Window Scale
				{Kind: 1, Length: 1},  // NOP
				{Kind: 1, Length: 1},  // NOP
				{Kind: 4, Length: 2},  // SACK Permitted
				{Kind: 8, Length: 10}, // Timestamps
			},
			IPTos:   0,
			IPFlags: 0x4000, // Don't Fragment
			Weight:  1.0,
		},

		// Windows 10
		{
			Name:            "Windows_10",
			TTL:             128,
			WindowSize:      64240,
			WindowScale:     8,
			MSS:             1460,
			SACKPermitted:   true,
			Timestamps:      true,
			NoDelay:         true,
			KeepAlive:       true,
			KeepAliveTime:   7200,
			KeepAliveProbes: 10,
			KeepAliveIntvl:  1,
			TCPOptions: []TCPOption{
				{Kind: 2, Length: 4},
				{Kind: 1, Length: 1},
				{Kind: 3, Length: 3},
				{Kind: 1, Length: 1},
				{Kind: 1, Length: 1},
				{Kind: 4, Length: 2},
				{Kind: 8, Length: 10},
			},
			IPTos:   0,
			IPFlags: 0x4000,
			Weight:  0.95,
		},

		// macOS Sonoma
		{
			Name:            "macOS_Sonoma",
			TTL:             64,
			WindowSize:      65535,
			WindowScale:     6,
			MSS:             1460,
			SACKPermitted:   true,
			Timestamps:      true,
			NoDelay:         false,
			KeepAlive:       true,
			KeepAliveTime:   7200,
			KeepAliveProbes: 8,
			KeepAliveIntvl:  75,
			TCPOptions: []TCPOption{
				{Kind: 2, Length: 4},
				{Kind: 4, Length: 2},
				{Kind: 8, Length: 10},
				{Kind: 1, Length: 1},
				{Kind: 3, Length: 3},
			},
			IPTos:   0,
			IPFlags: 0x4000,
			Weight:  0.9,
		},

		// macOS Ventura
		{
			Name:            "macOS_Ventura",
			TTL:             64,
			WindowSize:      65535,
			WindowScale:     6,
			MSS:             1460,
			SACKPermitted:   true,
			Timestamps:      true,
			NoDelay:         false,
			KeepAlive:       true,
			KeepAliveTime:   7200,
			KeepAliveProbes: 8,
			KeepAliveIntvl:  75,
			TCPOptions: []TCPOption{
				{Kind: 2, Length: 4},
				{Kind: 4, Length: 2},
				{Kind: 8, Length: 10},
				{Kind: 1, Length: 1},
				{Kind: 3, Length: 3},
			},
			IPTos:   0,
			IPFlags: 0x4000,
			Weight:  0.88,
		},

		// Linux (Ubuntu/Debian)
		{
			Name:            "Linux_Ubuntu",
			TTL:             64,
			WindowSize:      29200,
			WindowScale:     7,
			MSS:             1460,
			SACKPermitted:   true,
			Timestamps:      true,
			NoDelay:         false,
			KeepAlive:       true,
			KeepAliveTime:   7200,
			KeepAliveProbes: 9,
			KeepAliveIntvl:  75,
			TCPOptions: []TCPOption{
				{Kind: 2, Length: 4},
				{Kind: 4, Length: 2},
				{Kind: 8, Length: 10},
				{Kind: 1, Length: 1},
				{Kind: 3, Length: 3},
			},
			IPTos:   0,
			IPFlags: 0x4000,
			Weight:  0.92,
		},

		// Linux (RHEL/CentOS)
		{
			Name:            "Linux_RHEL",
			TTL:             64,
			WindowSize:      29200,
			WindowScale:     7,
			MSS:             1460,
			SACKPermitted:   true,
			Timestamps:      true,
			NoDelay:         false,
			KeepAlive:       true,
			KeepAliveTime:   7200,
			KeepAliveProbes: 9,
			KeepAliveIntvl:  75,
			TCPOptions: []TCPOption{
				{Kind: 2, Length: 4},
				{Kind: 4, Length: 2},
				{Kind: 8, Length: 10},
				{Kind: 1, Length: 1},
				{Kind: 3, Length: 3},
			},
			IPTos:   0,
			IPFlags: 0x4000,
			Weight:  0.85,
		},

		// Android
		{
			Name:            "Android",
			TTL:             64,
			WindowSize:      65535,
			WindowScale:     8,
			MSS:             1460,
			SACKPermitted:   true,
			Timestamps:      true,
			NoDelay:         false,
			KeepAlive:       true,
			KeepAliveTime:   7200,
			KeepAliveProbes: 9,
			KeepAliveIntvl:  75,
			TCPOptions: []TCPOption{
				{Kind: 2, Length: 4},
				{Kind: 4, Length: 2},
				{Kind: 8, Length: 10},
				{Kind: 1, Length: 1},
				{Kind: 3, Length: 3},
			},
			IPTos:   0,
			IPFlags: 0x4000,
			Weight:  0.93,
		},

		// iOS/iPadOS
		{
			Name:            "iOS",
			TTL:             64,
			WindowSize:      65535,
			WindowScale:     6,
			MSS:             1460,
			SACKPermitted:   true,
			Timestamps:      true,
			NoDelay:         false,
			KeepAlive:       true,
			KeepAliveTime:   7200,
			KeepAliveProbes: 8,
			KeepAliveIntvl:  75,
			TCPOptions: []TCPOption{
				{Kind: 2, Length: 4},
				{Kind: 4, Length: 2},
				{Kind: 8, Length: 10},
				{Kind: 1, Length: 1},
				{Kind: 3, Length: 3},
			},
			IPTos:   0,
			IPFlags: 0x4000,
			Weight:  0.91,
		},

		// FreeBSD
		{
			Name:            "FreeBSD",
			TTL:             64,
			WindowSize:      65535,
			WindowScale:     6,
			MSS:             1460,
			SACKPermitted:   true,
			Timestamps:      true,
			NoDelay:         false,
			KeepAlive:       true,
			KeepAliveTime:   7200,
			KeepAliveProbes: 8,
			KeepAliveIntvl:  75,
			TCPOptions: []TCPOption{
				{Kind: 2, Length: 4},
				{Kind: 1, Length: 1},
				{Kind: 3, Length: 3},
				{Kind: 1, Length: 1},
				{Kind: 1, Length: 1},
				{Kind: 4, Length: 2},
				{Kind: 8, Length: 10},
			},
			IPTos:   0,
			IPFlags: 0x4000,
			Weight:  0.70,
		},
	}

	tr.mutex.Lock()
	tr.profiles = profiles
	for _, profile := range profiles {
		tr.profileScores[profile.Name] = &TCPProfileScore{
			ProfileName:    profile.Name,
			SuccessRate:    0.5,
			latencyHistory: make([]time.Duration, 0, 100),
			resultHistory:  make([]bool, 0, 100),
		}
	}
	tr.mutex.Unlock()
}

// SelectBestProfile uses ML to select optimal profile
func (tr *TCPRandomizer) SelectBestProfile() *TCPProfile {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	type scored struct {
		profile *TCPProfile
		score   float64
	}

	var scoredList []scored

	for _, profile := range tr.profiles {
		score := profile.Weight

		if ps, exists := tr.profileScores[profile.Name]; exists {
			mlScore := tr.calculateProfileScore(ps)
			score = 0.4*profile.Weight + 0.6*mlScore
		}

		// Epsilon-greedy exploration
		if rand.Float64() < tr.explorationRate {
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

	tr.currentProfile = scoredList[bestIdx].profile
	return scoredList[bestIdx].profile
}

// calculateProfileScore computes ML score
func (tr *TCPRandomizer) calculateProfileScore(ps *TCPProfileScore) float64 {
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

// ApplyToDialer applies TCP profile to net.Dialer
func (tr *TCPRandomizer) ApplyToDialer(dialer *net.Dialer) error {
	profile := tr.SelectBestProfile()

	// Set timeout
	dialer.Timeout = 30 * time.Second

	// Set keep-alive
	if profile.KeepAlive {
		dialer.KeepAlive = time.Duration(profile.KeepAliveTime) * time.Second
	} else {
		dialer.KeepAlive = -1
	}

	// Set control function for socket options
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error

		err := c.Control(func(fd uintptr) {
			sockErr = tr.applySockopts(int(fd), profile)
		})

		if err != nil {
			return err
		}
		return sockErr
	}

	tr.currentProfile = profile
	return nil
}

// applySockopts applies socket options from profile
func (tr *TCPRandomizer) applySockopts(fd int, profile *TCPProfile) error {
	// Set TCP_NODELAY
	if profile.NoDelay {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
			// Non-fatal
		}
	}

	// Set SO_KEEPALIVE
	if profile.KeepAlive {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
			// Non-fatal
		}

		// Set TCP_KEEPIDLE (Linux)
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, 0x4, profile.KeepAliveTime)

		// Set TCP_KEEPINTVL (Linux)
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, 0x5, profile.KeepAliveIntvl)

		// Set TCP_KEEPCNT (Linux)
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, 0x6, profile.KeepAliveProbes)
	}

	// Set SO_RCVBUF (receive buffer)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, profile.WindowSize); err != nil {
		// Non-fatal
	}

	// Set SO_SNDBUF (send buffer)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, profile.WindowSize); err != nil {
		// Non-fatal
	}

	// Set IP_TTL
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, profile.TTL); err != nil {
		// Non-fatal
	}

	// Set IP_TOS
	if profile.IPTos != 0 {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, profile.IPTos); err != nil {
			// Non-fatal
		}
	}

	return nil
}

// ConfigureConnection applies profile to existing connection
func (tr *TCPRandomizer) ConfigureConnection(conn net.Conn) error {
	if tr.currentProfile == nil {
		tr.SelectBestProfile()
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("not a TCP connection")
	}

	// Set TCP_NODELAY
	if tr.currentProfile.NoDelay {
		if err := tcpConn.SetNoDelay(true); err != nil {
			// Non-fatal
		}
	}

	// Set keepalive
	if tr.currentProfile.KeepAlive {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			// Non-fatal
		}

		keepalivePeriod := time.Duration(tr.currentProfile.KeepAliveTime) * time.Second
		if err := tcpConn.SetKeepAlivePeriod(keepalivePeriod); err != nil {
			// Non-fatal
		}
	}

	// Set read/write buffers
	rawConn, err := tcpConn.SyscallConn()
	if err == nil {
		rawConn.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, tr.currentProfile.WindowSize)
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, tr.currentProfile.WindowSize)
		})
	}

	return nil
}

// VariateProfile adds random variation to profile
func (tr *TCPRandomizer) VariateProfile(profile *TCPProfile) *TCPProfile {
	variated := *profile

	// Vary TTL slightly (±2)
	ttlDelta := rand.Intn(5) - 2
	variated.TTL = profile.TTL + ttlDelta
	if variated.TTL < 32 {
		variated.TTL = 32
	}
	if variated.TTL > 255 {
		variated.TTL = 255
	}

	// Vary window size (±10%)
	variation := float64(profile.WindowSize) * 0.1
	delta := int(rand.Float64()*variation) - int(variation/2)
	variated.WindowSize = profile.WindowSize + delta
	if variated.WindowSize < 8192 {
		variated.WindowSize = 8192
	}

	// Vary keepalive time (±10%)
	if profile.KeepAlive {
		variation := float64(profile.KeepAliveTime) * 0.1
		delta := int(rand.Float64()*variation) - int(variation/2)
		variated.KeepAliveTime = profile.KeepAliveTime + delta
		if variated.KeepAliveTime < 60 {
			variated.KeepAliveTime = 60
		}
	}

	return &variated
}

// GetOptimalTTL calculates optimal TTL based on target distance
func (tr *TCPRandomizer) GetOptimalTTL(targetHost string) int {
	// Try to determine hop count via traceroute simulation
	// For now, use profile default with variation

	if tr.currentProfile == nil {
		tr.SelectBestProfile()
	}

	baseTTL := tr.currentProfile.TTL

	// Add slight random variation
	variation := rand.Intn(5) - 2
	ttl := baseTTL + variation

	if ttl < 32 {
		ttl = 32
	}
	if ttl > 255 {
		ttl = 255
	}

	return ttl
}

// GetOptimalWindowSize calculates optimal window size based on bandwidth
func (tr *TCPRandomizer) GetOptimalWindowSize(bandwidth float64, rtt time.Duration) int {
	// Bandwidth-Delay Product
	bdp := bandwidth * rtt.Seconds()

	// Convert to int, ensure reasonable range
	windowSize := int(bdp)

	if windowSize < 8192 {
		windowSize = 8192
	}
	if windowSize > 1048576 { // 1MB max
		windowSize = 1048576
	}

	return windowSize
}

// AdaptiveMSS calculates optimal MSS based on path MTU
func (tr *TCPRandomizer) AdaptiveMSS(mtu int) int {
	// MSS = MTU - IP header (20) - TCP header (20)
	mss := mtu - 40

	// Common MSS values
	if mss > 1460 {
		mss = 1460 // Ethernet standard
	} else if mss < 536 {
		mss = 536 // Minimum
	}

	return mss
}

// ReportResult updates ML model with usage result
func (tr *TCPRandomizer) ReportResult(success bool, latency time.Duration, blocked bool, targetHost string) {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	if tr.currentProfile == nil {
		return
	}

	profileName := tr.currentProfile.Name
	ps := tr.profileScores[profileName]

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
	ps.QValue = ps.QValue + tr.learningRate*(reward-ps.QValue)

	// Store result
	result := TCPResult{
		ProfileName: profileName,
		Success:     success,
		Latency:     latency,
		Blocked:     blocked,
		Timestamp:   time.Now(),
		TargetHost:  targetHost,
	}

	history := tr.usageHistory[profileName]
	history = append(history, result)
	if len(history) > 500 {
		history = history[1:]
	}
	tr.usageHistory[profileName] = history
}

// GetCurrentProfile returns current profile
func (tr *TCPRandomizer) GetCurrentProfile() *TCPProfile {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()
	return tr.currentProfile
}

// GetStats returns ML statistics
func (tr *TCPRandomizer) GetStats() map[string]interface{} {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	profileStats := make([]map[string]interface{}, 0)

	for _, ps := range tr.profileScores {
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
	if tr.currentProfile != nil {
		currentName = tr.currentProfile.Name
	}

	return map[string]interface{}{
		"total_profiles":   len(tr.profiles),
		"learning_rate":    tr.learningRate,
		"exploration_rate": tr.explorationRate,
		"current_profile":  currentName,
		"profile_stats":    profileStats,
	}
}

// GetProfileByName returns specific profile
func (tr *TCPRandomizer) GetProfileByName(name string) *TCPProfile {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	for _, profile := range tr.profiles {
		if profile.Name == name {
			return profile
		}
	}

	return nil
}

// ListProfiles returns all profile names
func (tr *TCPRandomizer) ListProfiles() []string {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	names := make([]string, len(tr.profiles))
	for i, profile := range tr.profiles {
		names[i] = profile.Name
	}

	return names
}

// DetectOptimalProfile analyzes target and selects best profile
func (tr *TCPRandomizer) DetectOptimalProfile(targetHost string, targetPort int) *TCPProfile {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	// Check history for this target
	bestProfile := tr.profiles[0]
	bestScore := 0.0

	for _, profile := range tr.profiles {
		score := profile.Weight * 0.4

		// Check usage history for this target
		if history, exists := tr.usageHistory[profile.Name]; exists {
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
				if ps, exists := tr.profileScores[profile.Name]; exists {
					score += ps.SuccessRate * 0.6
				}
			}
		}

		if score > bestScore {
			bestScore = score
			bestProfile = profile
		}
	}

	return bestProfile
}

// CalculateRTT estimates RTT based on latency history
func (tr *TCPRandomizer) CalculateRTT() time.Duration {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	if tr.currentProfile == nil {
		return 100 * time.Millisecond
	}

	ps := tr.profileScores[tr.currentProfile.Name]
	if ps.AvgLatency > 0 {
		return ps.AvgLatency
	}

	return 100 * time.Millisecond
}

// GetBestProfiles returns top N performing profiles
func (tr *TCPRandomizer) GetBestProfiles(n int) []*TCPProfile {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	type scored struct {
		profile *TCPProfile
		score   float64
	}

	var scoredList []scored

	for _, profile := range tr.profiles {
		score := 0.0
		if ps, exists := tr.profileScores[profile.Name]; exists {
			score = tr.calculateProfileScore(ps)
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

	result := make([]*TCPProfile, n)
	for i := 0; i < n; i++ {
		result[i] = scoredList[i].profile
	}

	return result
}

// OptimizeForLatency adjusts profile for low-latency connections
func (tr *TCPRandomizer) OptimizeForLatency(profile *TCPProfile, targetLatency time.Duration) *TCPProfile {
	optimized := *profile

	if targetLatency < 50*time.Millisecond {
		// Low latency - smaller window, more aggressive
		optimized.WindowSize = int(float64(profile.WindowSize) * 0.7)
		optimized.NoDelay = true
	} else if targetLatency > 200*time.Millisecond {
		// High latency - larger window
		optimized.WindowSize = int(float64(profile.WindowSize) * 1.3)
	}

	return &optimized
}

// _ ensures unsafe is marked as used (for future raw socket operations)
var _ = unsafe.Sizeof(0)
