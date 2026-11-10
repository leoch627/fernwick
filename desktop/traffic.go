package main

import (
	"context"
	"sync/atomic"
	"time"

	"work.starrail/client/desktop/core"
)

// watchTraffic shows the connection's speed once a second while connected: beside the
// tray icon on macOS, in the tray tooltip on Windows, and in the window.
func (s *shell) watchTraffic(ctx context.Context, tray *trayMenu) {
	var connected atomic.Bool
	s.controller.Subscribe(func(view core.AppView) { connected.Store(view.Connection == "Connected") })
	connected.Store(s.controller.View().Connection == "Connected")
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var meter core.TrafficMeter
		showing := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !connected.Load() {
				if showing {
					showing = false
					meter.Reset()
					s.showTraffic(tray, nil)
				}
				continue
			}
			sample, ok := s.controller.Traffic(ctx)
			if !ok {
				continue
			}
			rate := meter.Add(sample)
			showing = true
			s.showTraffic(tray, &rate)
		}
	}()
}

// showTraffic updates every place the speed shows; nil hides it.
func (s *shell) showTraffic(tray *trayMenu, rate *core.TrafficRate) {
	if tray != nil {
		tray.setSpeed(rate)
	}
	s.mu.Lock()
	active := s.window != nil && !s.quitting
	s.mu.Unlock()
	if !active {
		return
	}
	var payload any
	if rate != nil {
		payload = map[string]string{"up": core.FormatRate(rate.Up), "down": core.FormatRate(rate.Down)}
	}
	s.app.Event.Emit("starrail:traffic", payload)
}
