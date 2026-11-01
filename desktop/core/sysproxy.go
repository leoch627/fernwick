package core

import (
	"context"
	"encoding/json"
	"io"
	"os"
)

// SystemProxy points the user's system proxy at a loopback port and puts back what was
// there before. It runs as the user: no platform needs administrator rights for this.
// Saved settings are opaque JSON that only the same platform's implementation reads.
type SystemProxy interface {
	Snapshot(ctx context.Context) (json.RawMessage, error)
	Apply(ctx context.Context, saved json.RawMessage, port int) error
	Restore(ctx context.Context, saved json.RawMessage) error
}

// proxyJournal is written before the system proxy changes and removed once the previous
// settings are back, so a crash or power loss is undone at the next start.
type proxyJournal struct {
	SchemaVersion int             `json:"schemaVersion"`
	Port          int             `json:"port"`
	Saved         json.RawMessage `json:"saved"`
}

func readProxyJournal(path string) (*proxyJournal, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return nil, NewAppError("STORAGE_FAILED")
	}
	var journal proxyJournal
	if err = json.Unmarshal(data, &journal); err != nil || journal.SchemaVersion != 1 || len(journal.Saved) == 0 {
		return nil, NewAppError("STORAGE_FAILED")
	}
	return &journal, nil
}
func writeProxyJournal(path string, journal proxyJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return AtomicWrite(path, data, nil)
}
