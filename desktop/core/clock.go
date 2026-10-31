package core

import (
	"math/rand/v2"
	"sync"
	"time"
)

const clockRollbackTolerance int64 = 120000

// ConservativeClock combines a persistent wall-clock high water mark with Go's
// monotonic elapsed time. It cannot turn a clock rollback into longer access.
type ConservativeClock struct {
	mu         sync.Mutex
	wall       func() int64
	mono       func() int64
	anchorWall int64
	anchorMono int64
	upper      int64
	trusted    bool
}

func NewConservativeClock(savedUpper int64) *ConservativeClock {
	anchor := time.Now()
	return NewConservativeClockWithSources(savedUpper, func() int64 { return time.Now().UnixMilli() }, func() int64 { return time.Since(anchor).Milliseconds() })
}

func NewConservativeClockWithSources(savedUpper int64, wall, mono func() int64) *ConservativeClock {
	anchorWall, anchorMono := wall(), mono()
	return &ConservativeClock{
		wall: wall, mono: mono, anchorWall: anchorWall, anchorMono: anchorMono,
		upper: max(savedUpper, anchorWall), trusted: anchorWall >= savedUpper-clockRollbackTolerance,
	}
}

func (clock *ConservativeClock) Now() int64 {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	wall := clock.wall()
	monotonic := clock.anchorWall + max(0, clock.mono()-clock.anchorMono)
	if wall < clock.upper-clockRollbackTolerance || wall < monotonic-clockRollbackTolerance {
		clock.trusted = false
	}
	clock.upper = max(clock.upper, wall, monotonic)
	return clock.upper
}

func (clock *ConservativeClock) HighWater() int64 { return clock.Now() }

func (clock *ConservativeClock) RestoreUpper(saved int64) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.upper = max(clock.upper, saved)
	if clock.wall() < clock.upper-clockRollbackTolerance {
		clock.trusted = false
	}
}

func (clock *ConservativeClock) Trusted() bool {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.trusted
}

func (clock *ConservativeClock) RevalidateAfterOnlineSync() {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	// A successful network request is not an authoritative server timestamp.
	wall := clock.wall()
	if wall < clock.upper-clockRollbackTolerance {
		return
	}
	clock.anchorWall, clock.anchorMono = max(wall, clock.upper), clock.mono()
	clock.trusted = true
}

func Jitter(seconds int) time.Duration { return JitterWithRandom(seconds, rand.Float64) }

func JitterWithRandom(seconds int, random func() float64) time.Duration {
	return time.Duration(float64(seconds) * float64(time.Second) * (0.9 + random()*0.2))
}
