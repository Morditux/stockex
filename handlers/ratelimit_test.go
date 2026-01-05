package handlers

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	// Create a custom limiter for testing to avoid global state interference
	// and to use shorter durations.
	limiter := &rateLimiter{
		attempts: make(map[string]*attemptData),
		blocked:  make(map[string]time.Time),
	}

	// We can't easily inject time into the current implementation without dependency injection,
	// but we can test the logic flow.

	ip := "127.0.0.1"

	// 1. Initial state: Allowed
	if !limiter.Allow(ip) {
		t.Errorf("Expected IP to be allowed initially")
	}

	// 2. Record 4 failures (less than maxAttempts=5)
	for i := 0; i < 4; i++ {
		limiter.RecordFailure(ip)
	}
	if !limiter.Allow(ip) {
		t.Errorf("Expected IP to be allowed after 4 failures")
	}

	// 3. Record 5th failure -> Should block
	limiter.RecordFailure(ip)
	if limiter.Allow(ip) {
		t.Errorf("Expected IP to be blocked after 5 failures")
	}

	// 4. Reset -> Should allow
	limiter.Reset(ip)
	if !limiter.Allow(ip) {
		t.Errorf("Expected IP to be allowed after reset")
	}
}

func TestRateLimiterParallel(t *testing.T) {
	limiter := &rateLimiter{
		attempts: make(map[string]*attemptData),
		blocked:  make(map[string]time.Time),
	}
	ip := "10.0.0.1"

	var wg sync.WaitGroup
	// Simulate parallel requests
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter.RecordFailure(ip)
		}()
	}
	wg.Wait()

	if limiter.Allow(ip) {
		t.Errorf("Expected IP to be blocked after concurrent failures")
	}
}
