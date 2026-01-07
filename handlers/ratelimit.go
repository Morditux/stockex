package handlers

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type attemptData struct {
	count        int
	firstAttempt time.Time
}

type rateLimiter struct {
	sync.Mutex
	attempts map[string]*attemptData
	blocked  map[string]time.Time
}

// loginLimiter is a package-private variable shared by LoginHandler and APILoginHandler
var loginLimiter = &rateLimiter{
	attempts: make(map[string]*attemptData),
	blocked:  make(map[string]time.Time),
}

// signupLimiter is shared by SignupHandler and APISignupHandler
var signupLimiter = &rateLimiter{
	attempts: make(map[string]*attemptData),
	blocked:  make(map[string]time.Time),
}

const (
	maxAttempts    = 5
	blockDuration  = 15 * time.Minute
	windowDuration = 15 * time.Minute
)

// Allow returns false if the IP is currently blocked.
// It also cleans up expired blocks.
func (r *rateLimiter) Allow(ip string) bool {
	r.Lock()
	defer r.Unlock()

	if unblockTime, ok := r.blocked[ip]; ok {
		if time.Now().Before(unblockTime) {
			return false
		}
		// Block expired
		delete(r.blocked, ip)
		delete(r.attempts, ip)
	}
	return true
}

// RecordFailure increments the failure count and blocks if threshold reached.
func (r *rateLimiter) RecordFailure(ip string) {
	r.Lock()
	defer r.Unlock()

	// Cleanup if map gets too large (simple DoS protection)
	if len(r.attempts) > 10000 {
		// Naive cleanup: just clear it. This allows a window of bypass but saves memory.
		// A better approach would be to iterate and delete old entries, but that's O(N).
		// Given strict line limits, a full reset is a safe fallback.
		r.attempts = make(map[string]*attemptData)
	}

	data, exists := r.attempts[ip]
	if !exists || time.Since(data.firstAttempt) > windowDuration {
		r.attempts[ip] = &attemptData{count: 1, firstAttempt: time.Now()}
	} else {
		data.count++
		if data.count >= maxAttempts {
			r.blocked[ip] = time.Now().Add(blockDuration)
		}
	}
}

// Reset clears the counter for an IP (used on successful login).
func (r *rateLimiter) Reset(ip string) {
	r.Lock()
	defer r.Unlock()
	delete(r.attempts, ip)
	delete(r.blocked, ip)
}

func getClientIP(r *http.Request) string {
	// Standard library method to get IP (handles IP:Port)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
