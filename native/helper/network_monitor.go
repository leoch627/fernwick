package main

import (
	"context"
	"time"
)

// Observe route and resolver changes even when interface names/addresses did not change.
// A stable second observation coalesces NetworkManager/SCM/launchd bursts.
func (s *service) monitorNetwork(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	currentID, baseline, pending := "", "", ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			j := s.journal
			active := j != nil && s.state == "Connected" && !s.cleaning
			s.mu.Unlock()
			if !active {
				currentID = ""
				baseline = ""
				pending = ""
				continue
			}
			probe, cancel := context.WithTimeout(ctx, 3*time.Second)
			fingerprint, e := platformNetworkFingerprint(probe, j.Interface)
			cancel()
			if e != nil {
				fingerprint = "unavailable"
			}
			s.mu.Lock()
			valid := s.journal == j && s.state == "Connected" && !s.cleaning
			s.mu.Unlock()
			if !valid {
				continue
			}
			if currentID != j.ID {
				currentID = j.ID
				baseline = fingerprint
				pending = ""
				continue
			}
			if fingerprint == baseline {
				pending = ""
				continue
			}
			if pending != fingerprint {
				pending = fingerprint
				continue
			}
			s.mu.Lock()
			if s.journal == j && s.state == "Connected" && !s.cleaning {
				s.cleaning = true
				if s.cancel != nil {
					s.cancel()
				}
				s.mu.Unlock()
				if e := s.cleanup(); e != nil {
					logCode("NETWORK_RECOVERY_REQUIRED")
				}
			} else {
				s.mu.Unlock()
			}
			currentID = ""
		}
	}
}
