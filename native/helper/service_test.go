package main

import (
	"strings"
	"testing"
	"time"
)

var owner = Peer{PID: 100, User: "501", Birth: "1", Executable: "/opt/StarRail/starrail"}
var intruder = Peer{PID: 200, User: "502", Birth: "2", Executable: "/opt/StarRail/starrail"}

func ownedService(t *testing.T) *service {
	t.Helper()
	withBuild(t, Build{ProductID: "starrail-test", DisplayName: "StarRail Test", HelperLabel: "work.starrail.test.helper", BuildID: "build-1", Version: "0.1.0"})
	withInstalled(t, Installation{BuildID: "build-1"})
	return &service{state: "Connected", journal: &Journal{Owner: owner}, ticket: "ticket-1"}
}
func call(s *service, p Peer, r Request) Response {
	r.Protocol, r.ProductID = protocolVersion, build.ProductID
	if r.ID == "" {
		r.ID = "request-1"
	}
	return s.request(p, r)
}

func TestRequestEnvelope(t *testing.T) {
	s := ownedService(t)
	if r := s.request(owner, Request{Protocol: protocolVersion + 1, ProductID: build.ProductID, ID: "1", Action: "status"}); r.OK || r.Error != "COMPONENTS_UNAVAILABLE" {
		t.Errorf("protocol mismatch: %+v", r)
	}
	if r := s.request(owner, Request{Protocol: protocolVersion, ProductID: "other", ID: "1", Action: "status"}); r.OK || r.Error != "COMPONENTS_UNAVAILABLE" {
		t.Errorf("product mismatch: %+v", r)
	}
	if r := call(s, owner, Request{ID: strings.Repeat("x", 129), Action: "status"}); r.OK {
		t.Errorf("oversized id accepted")
	}
	if r := call(s, owner, Request{Action: "status"}); !r.OK || !r.Owned || !r.Ready || r.Ticket != "" {
		t.Errorf("owner status: %+v", r)
	}
	if r := call(s, intruder, Request{Action: "status"}); !r.OK || r.Owned {
		t.Errorf("intruder status reports ownership: %+v", r)
	}
}

func TestOnlyOwnerCanControlConnection(t *testing.T) {
	for _, action := range []string{"heartbeat", "protect", "start", "probe", "commit", "unknown"} {
		s := ownedService(t)
		if r := call(s, intruder, Request{Action: action, Ticket: "ticket-1"}); r.OK || r.Error != "NETWORK_CONFLICT" {
			t.Errorf("%s by intruder with stolen ticket: %+v", action, r)
		}
		if r := call(s, owner, Request{Action: action, Ticket: "wrong"}); r.OK || r.Error != "NETWORK_CONFLICT" {
			t.Errorf("%s by owner with wrong ticket: %+v", action, r)
		}
		if r := call(s, owner, Request{Action: action}); r.OK || r.Error != "NETWORK_CONFLICT" {
			t.Errorf("%s by owner without ticket: %+v", action, r)
		}
	}
	s := ownedService(t)
	if r := call(s, owner, Request{Action: "unknown", Ticket: "ticket-1"}); r.OK || r.Error != "INVALID_INPUT" {
		t.Errorf("unknown action: %+v", r)
	}
}

func TestIntruderCannotStopOwnedConnection(t *testing.T) {
	for _, action := range []string{"stop", "recover"} {
		s := ownedService(t)
		cancelled := false
		s.cancel = func() { cancelled = true }
		if r := call(s, intruder, Request{Action: action}); r.OK || r.Error != "NETWORK_CONFLICT" {
			t.Errorf("%s: %+v", action, r)
		}
		if cancelled || s.journal == nil {
			t.Errorf("%s by intruder interrupted the connection", action)
		}
	}
}

func TestBusyServiceRefusesNewTransactions(t *testing.T) {
	c := validCandidate()
	for _, action := range []string{"prepare", "stage-update"} {
		s := ownedService(t)
		if r := call(s, owner, Request{Action: action, Candidate: &c}); r.OK || r.Error != "NETWORK_CONFLICT" {
			t.Errorf("%s while connected: %+v", action, r)
		}
		s = ownedService(t)
		s.journal, s.state = nil, "RecoveryRequired"
		if r := call(s, intruder, Request{Action: action, Candidate: &c}); r.OK || r.Error != "NETWORK_CONFLICT" {
			t.Errorf("%s during recovery: %+v", action, r)
		}
	}
}

func TestHeartbeatBoundsAuthorization(t *testing.T) {
	s := ownedService(t)
	until := time.Now().Add(time.Hour).UnixMilli()
	if r := call(s, owner, Request{Action: "heartbeat", Ticket: "ticket-1", AuthorizedUntil: until}); !r.OK {
		t.Fatalf("heartbeat: %+v", r)
	}
	if s.authUntil != until || s.heartbeat.IsZero() || time.Until(s.authDeadline) > time.Hour {
		t.Fatalf("heartbeat state: until=%d deadline=%v", s.authUntil, s.authDeadline)
	}
	if r := call(s, owner, Request{Action: "heartbeat", Ticket: "ticket-1", AuthorizedUntil: time.Now().Add(maxAuthorization + time.Hour).UnixMilli()}); !r.OK {
		t.Fatalf("heartbeat: %+v", r)
	}
	if s.authUntil != until {
		t.Fatalf("authorization extended beyond the maximum to %d", s.authUntil)
	}
	if r := call(s, owner, Request{Action: "heartbeat", Ticket: "ticket-1", AuthorizedUntil: -1}); !r.OK || s.authUntil != until {
		t.Fatalf("negative authorization accepted: %+v until=%d", r, s.authUntil)
	}
}
