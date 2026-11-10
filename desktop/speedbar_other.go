//go:build !darwin

package main

import "work.starrail/client/desktop/core"

// Other systems have no menu bar text; the tray tooltip and the window show the speed.
type speedBar struct{}

func newSpeedBar(func()) *speedBar      { return &speedBar{} }
func (*speedBar) show(core.TrafficRate) {}
func (*speedBar) hide()                 {}
