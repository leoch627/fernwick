package main

import (
	"crypto/rand"
	"errors"
	"sync"
	"work.starrail/client/desktop/core"
)

var errSecretMissing = errors.New("session key missing")

type systemKeyProvider struct {
	mu      sync.Mutex
	dir     string
	service string
	cached  []byte
}

func (p *systemKeyProvider) Key(create bool) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.cached) == 32 {
		return append([]byte{}, p.cached...), nil
	}
	key, err := readSystemSecret(p.dir, p.service, "session-key")
	if errors.Is(err, errSecretMissing) && create {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err == nil {
			err = writeSystemSecret(p.dir, p.service, "session-key", key)
		}
	}
	if err != nil {
		return nil, core.ErrKeyUnavailable
	}
	if len(key) != 32 {
		return nil, core.NewAppError("STORAGE_LOCKED")
	}
	p.cached = append([]byte{}, key...)
	return append([]byte{}, key...), nil
}
