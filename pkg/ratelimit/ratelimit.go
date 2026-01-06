package ratelimit

import (
	"sync"
	"time"
)

type RateLimiter struct {
	rate     int
	interval time.Duration
	tokens   int
	mu       sync.Mutex
	lastTime time.Time
}

func New(rate int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		rate:     rate,
		interval: interval,
		tokens:   rate,
		lastTime: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime)

	if elapsed >= rl.interval {
		rl.tokens = rl.rate
		rl.lastTime = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

func (rl *RateLimiter) Wait() {
	for !rl.Allow() {
		time.Sleep(10 * time.Millisecond)
	}
}

func (rl *RateLimiter) SetRate(rate int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rate = rate
}

type TokenBucket struct {
	capacity int
	tokens   int
	rate     int
	mu       sync.Mutex
	ticker   *time.Ticker
	done     chan bool
}

func NewTokenBucket(capacity, rate int) *TokenBucket {
	tb := &TokenBucket{
		capacity: capacity,
		tokens:   capacity,
		rate:     rate,
		done:     make(chan bool),
	}
	tb.start()
	return tb
}

func (tb *TokenBucket) start() {
	tb.ticker = time.NewTicker(time.Second / time.Duration(tb.rate))
	go func() {
		for {
			select {
			case <-tb.ticker.C:
				tb.addToken()
			case <-tb.done:
				return
			}
		}
	}()
}

func (tb *TokenBucket) addToken() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.tokens < tb.capacity {
		tb.tokens++
	}
}

func (tb *TokenBucket) Take() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}
	return false
}

func (tb *TokenBucket) Wait() {
	for !tb.Take() {
		time.Sleep(10 * time.Millisecond)
	}
}

func (tb *TokenBucket) Stop() {
	tb.ticker.Stop()
	close(tb.done)
}
