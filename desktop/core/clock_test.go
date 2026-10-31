package core

import (
	"sync"
	"testing"
	"time"
)

func TestConservativeClockRollback(t *testing.T) {
	wall, mono := authTestNow, int64(0)
	clock := NewConservativeClockWithSources(authTestNow, func() int64 { return wall }, func() int64 { return mono })
	mono, wall = 60000, wall-3600000
	if clock.Now() != authTestNow+60000 || clock.Trusted() {
		t.Fatal("large rollback must retain monotonic elapsed time and distrust wall time")
	}
	clock.RevalidateAfterOnlineSync()
	if clock.Trusted() {
		t.Fatal("network success cannot validate a still-rolled-back clock")
	}
	wall = authTestNow + 60000
	clock.RevalidateAfterOnlineSync()
	if !clock.Trusted() || clock.HighWater() != wall {
		t.Fatal("corrected wall time did not recover trust")
	}
	mono += 1000
	if clock.Now() != wall+1000 {
		t.Fatal("revalidation lost the monotonic anchor")
	}
}

func TestConservativeClockRestartsAndThreshold(t *testing.T) {
	for _, delta := range []int64{-600000, -120001, -120000, -60000, 0, 60000} {
		clock := NewConservativeClockWithSources(authTestNow, func() int64 { return authTestNow + delta }, func() int64 { return 0 })
		if got, want := clock.Now(), max(authTestNow, authTestNow+delta); got != want {
			t.Errorf("delta %d: now=%d, want %d", delta, got, want)
		}
		if clock.Trusted() != (delta >= -120000) {
			t.Errorf("delta %d: incorrect trust", delta)
		}
	}
}

func TestConservativeClockNeverMovesBackwards(t *testing.T) {
	wall, mono := authTestNow, int64(0)
	clock := NewConservativeClockWithSources(0, func() int64 { return wall }, func() int64 { return mono })
	wall += 3600000
	upper := clock.Now()
	wall -= 3600000
	mono += 300000
	if clock.Now() != upper || clock.Trusted() {
		t.Fatal("a backwards correction extended authorization")
	}
}

func TestConservativeClockConcurrentReaders(t *testing.T) {
	clock := NewConservativeClock(authTestNow)
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			previous := int64(0)
			for range 100 {
				now := clock.Now()
				if now < previous {
					t.Error("time moved backwards")
				}
				previous = now
				clock.Trusted()
				clock.RevalidateAfterOnlineSync()
			}
		})
	}
	readers.Wait()
}

func TestJitterBounds(t *testing.T) {
	for _, test := range []struct {
		random float64
		want   time.Duration
	}{{0, 270 * time.Second}, {0.5, 300 * time.Second}, {1, 330 * time.Second}} {
		if got := JitterWithRandom(300, func() float64 { return test.random }); got != test.want {
			t.Errorf("random %v: got %v, want %v", test.random, got, test.want)
		}
	}
}
