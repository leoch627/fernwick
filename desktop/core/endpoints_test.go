package core

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestEndpointStickyExpiryAndPolicy(t *testing.T) {
	f := newSignedFixture(t)
	var clock atomic.Int64
	clock.Store(f.now)
	pool := NewEndpointPool(f.build.APIEndpoints, clock.Load)
	if pool.Candidates(nil)[0].ID != "primary" {
		t.Fatal("priority ignored")
	}
	pool.Success("backup")
	if pool.Candidates(nil)[0].ID != "backup" {
		t.Fatal("sticky endpoint ignored")
	}
	policy := f.policy
	policy.Endpoints.TemporarilyDisabledIDs = []string{"backup"}
	if got := pool.Candidates(&policy); len(got) != 1 || got[0].ID != "primary" {
		t.Fatalf("disabled sticky endpoint selected: %+v", got)
	}
	clock.Add(600000)
	if pool.Candidates(nil)[0].ID != "primary" {
		t.Fatal("sticky expiry extended")
	}
	policy.Endpoints.OrderedIDs = []string{"backup", "primary"}
	policy.Endpoints.TemporarilyDisabledIDs = []string{}
	if pool.Candidates(&policy)[0].ID != "backup" {
		t.Fatal("policy ordering ignored")
	}
	pool.Success("backup")
	pool.Failure("backup")
	if pool.Candidates(nil)[0].ID != "primary" {
		t.Fatal("failure retained stickiness")
	}
}

func TestEndpointCircuitBackoffAndReset(t *testing.T) {
	f := newSignedFixture(t)
	var clock atomic.Int64
	clock.Store(f.now)
	pool := NewEndpointPool(f.build.APIEndpoints, clock.Load)
	for _, delay := range []int64{60000, 120000, 240000, 300000, 300000} {
		for range 3 {
			pool.Failure("primary")
		}
		if got := pool.Candidates(nil); len(got) != 1 || got[0].ID != "backup" {
			t.Fatalf("circuit not open: %+v", got)
		}
		clock.Add(delay - 1)
		if len(pool.Candidates(nil)) != 1 {
			t.Fatal("circuit opened early")
		}
		clock.Add(1)
		if pool.Candidates(nil)[0].ID != "primary" {
			t.Fatal("circuit did not reopen on deadline")
		}
	}
	pool.Success("primary")
	for range 3 {
		pool.Failure("primary")
	}
	clock.Add(60000)
	if pool.Candidates(nil)[0].ID != "primary" {
		t.Fatal("success did not reset backoff")
	}
}

func TestEndpointPoolConcurrentReadersAndWriters(t *testing.T) {
	f := newSignedFixture(t)
	pool := NewEndpointPool(f.build.APIEndpoints, func() int64 { return f.now })
	var wg sync.WaitGroup
	for i := range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				switch i % 3 {
				case 0:
					pool.Success("backup")
				case 1:
					pool.Failure("primary")
				case 2:
					_ = pool.Candidates(&f.policy)
				}
			}
		}()
	}
	wg.Wait()
	input := append([]APIEndpoint{}, f.build.APIEndpoints...)
	other := NewEndpointPool(input, nil)
	input[0].ID = "mutated"
	if other.Candidates(nil)[0].ID != "primary" {
		t.Fatal("caller mutated endpoints")
	}
	empty := NewEndpointPool(nil, nil).Candidates(nil)
	if empty == nil || len(empty) != 0 {
		t.Fatal("empty candidates must be non-null")
	}
}
