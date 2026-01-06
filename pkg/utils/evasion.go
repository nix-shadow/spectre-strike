package utils

import (
	"math/rand"
	"time"
)

// Evasion strategies for rate limiting and bot detection

type EvasionStrategy struct {
	Name             string
	BaseDelay        time.Duration
	JitterPercent    float64
	BurstSize        int
	BurstInterval    time.Duration
	ThinkTimeEnabled bool
	ThinkTimeMin     time.Duration
	ThinkTimeMax     time.Duration
}

var evasionStrategies = []EvasionStrategy{
	{
		Name:             "Aggressive",
		BaseDelay:        50 * time.Millisecond,
		JitterPercent:    0.2,
		BurstSize:        100,
		BurstInterval:    1 * time.Second,
		ThinkTimeEnabled: false,
	},
	{
		Name:             "Balanced",
		BaseDelay:        100 * time.Millisecond,
		JitterPercent:    0.3,
		BurstSize:        50,
		BurstInterval:    2 * time.Second,
		ThinkTimeEnabled: true,
		ThinkTimeMin:     100 * time.Millisecond,
		ThinkTimeMax:     500 * time.Millisecond,
	},
	{
		Name:             "Stealth",
		BaseDelay:        500 * time.Millisecond,
		JitterPercent:    0.5,
		BurstSize:        10,
		BurstInterval:    5 * time.Second,
		ThinkTimeEnabled: true,
		ThinkTimeMin:     500 * time.Millisecond,
		ThinkTimeMax:     2 * time.Second,
	},
	{
		Name:             "Human-like",
		BaseDelay:        1 * time.Second,
		JitterPercent:    0.7,
		BurstSize:        5,
		BurstInterval:    10 * time.Second,
		ThinkTimeEnabled: true,
		ThinkTimeMin:     2 * time.Second,
		ThinkTimeMax:     5 * time.Second,
	},
}

// GetRandomEvasionStrategy returns a random evasion strategy
func GetRandomEvasionStrategy() EvasionStrategy {
	return evasionStrategies[rand.Intn(len(evasionStrategies))]
}

// CalculateDelay calculates the next delay with jitter
func (e *EvasionStrategy) CalculateDelay() time.Duration {
	jitter := e.JitterPercent * float64(e.BaseDelay)
	randomJitter := time.Duration(rand.Float64()*jitter*2 - jitter)
	return e.BaseDelay + randomJitter
}

// ShouldThink determines if a "think time" delay should be applied
func (e *EvasionStrategy) ShouldThink() bool {
	if !e.ThinkTimeEnabled {
		return false
	}
	// 20% chance to think
	return rand.Float64() < 0.2
}

// GetThinkTime returns a random think time duration
func (e *EvasionStrategy) GetThinkTime() time.Duration {
	if !e.ThinkTimeEnabled {
		return 0
	}
	diff := e.ThinkTimeMax - e.ThinkTimeMin
	return e.ThinkTimeMin + time.Duration(rand.Float64()*float64(diff))
}

// TokenBucket implements a token bucket for rate limiting
type TokenBucket struct {
	capacity   int
	tokens     int
	refillRate time.Duration
	lastRefill time.Time
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(capacity int, refillRate time.Duration) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// TryConsume tries to consume a token from the bucket
func (tb *TokenBucket) TryConsume() bool {
	tb.refill()
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}
	return false
}

// refill adds tokens based on time passed
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	tokensToAdd := int(elapsed / tb.refillRate)

	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}
}

// DistributedDelay implements intelligent delay distribution
type DistributedDelay struct {
	workers     int
	targetRPS   int
	delayPerReq time.Duration
}

// NewDistributedDelay creates a new distributed delay calculator
func NewDistributedDelay(workers, targetRPS int) *DistributedDelay {
	totalRequestsPerSecond := targetRPS
	delayPerReq := time.Second / time.Duration(totalRequestsPerSecond)

	return &DistributedDelay{
		workers:     workers,
		targetRPS:   targetRPS,
		delayPerReq: delayPerReq,
	}
}

// GetDelay returns the delay for a worker
func (dd *DistributedDelay) GetDelay(workerID int) time.Duration {
	// Add worker-specific offset to prevent synchronized requests
	offset := time.Duration(workerID) * (dd.delayPerReq / time.Duration(dd.workers))
	return dd.delayPerReq + offset
}
