package main

import (
	"context"
	"encoding/json"
	"work.starrail/client/desktop/core"
)

// Bridge exposes only the frozen command/view contract to the webview.
type Bridge struct {
	controller *core.ClientController
	ready      chan struct{}
}

func (b *Bridge) Command(ctx context.Context, input json.RawMessage) core.CommandResult {
	cancelled := func() core.CommandResult {
		return core.CommandResult{OK: false, State: b.controller.View(), Error: "CANCELLED"}
	}
	if ctx.Err() != nil {
		return cancelled()
	}
	select {
	case <-b.ready:
		if ctx.Err() != nil {
			return cancelled()
		}
		return b.controller.Command(ctx, input)
	case <-ctx.Done():
		return cancelled()
	}
}
