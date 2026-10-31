package core

import (
	"sort"
	"sync"
	"time"
)

type endpointHealth struct {
	failures     int
	blockedUntil int64
	opens        int
}

type EndpointPool struct {
	mu          sync.Mutex
	endpoints   []APIEndpoint
	now         func() int64
	health      map[string]endpointHealth
	stickyID    string
	stickyUntil int64
}

func NewEndpointPool(endpoints []APIEndpoint, now func() int64) *EndpointPool {
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return &EndpointPool{endpoints: append([]APIEndpoint{}, endpoints...), now: now, health: make(map[string]endpointHealth)}
}

func (p *EndpointPool) Candidates(policy *Policy) []APIEndpoint {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	ordered := append([]APIEndpoint{}, p.endpoints...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	ids := make([]string, 0, len(ordered))
	for _, endpoint := range ordered {
		ids = append(ids, endpoint.ID)
	}
	disabled := make(map[string]bool)
	if policy != nil {
		ids = policy.Endpoints.OrderedIDs
		for _, id := range policy.Endpoints.TemporarilyDisabledIDs {
			disabled[id] = true
		}
	}
	result := make([]APIEndpoint, 0, len(ids))
	for _, id := range ids {
		for _, endpoint := range p.endpoints {
			if endpoint.ID == id && !disabled[id] && p.health[id].blockedUntil <= now {
				result = append(result, endpoint)
				break
			}
		}
	}
	if p.stickyUntil > now {
		sort.SliceStable(result, func(i, j int) bool { return result[i].ID == p.stickyID && result[j].ID != p.stickyID })
	}
	return result
}

func (p *EndpointPool) Success(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.health, id)
	p.stickyID, p.stickyUntil = id, p.now()+600000
}

func (p *EndpointPool) Failure(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	health := p.health[id]
	health.failures++
	if health.failures >= 3 {
		// Saturate opens rather than overflowing a shift after repeated failures.
		delay := min(int64(60000)<<health.opens, int64(300000))
		health.blockedUntil = p.now() + delay
		health.opens = min(health.opens+1, 3)
		health.failures = 0
	}
	p.health[id] = health
	if p.stickyID == id {
		p.stickyID, p.stickyUntil = "", 0
	}
}
