package main

/*
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>
void speedBarShow(const char *up, const char *down, int upLevel, int downLevel);
void speedBarHide(void);
*/
import "C"

import (
	"sync"
	"unsafe"

	"work.starrail/client/desktop/core"
)

// speedBar is the menu bar's speed readout on macOS (speedbar_darwin.m).
type speedBar struct{}

var speedBarClick struct {
	sync.Mutex
	handler func()
}

func newSpeedBar(click func()) *speedBar {
	speedBarClick.Lock()
	speedBarClick.handler = click
	speedBarClick.Unlock()
	return &speedBar{}
}

func (*speedBar) show(rate core.TrafficRate) {
	up, down := C.CString(core.FormatRate(rate.Up)), C.CString(core.FormatRate(rate.Down))
	defer C.free(unsafe.Pointer(up))
	defer C.free(unsafe.Pointer(down))
	C.speedBarShow(up, down, C.int(core.RateLevel(rate.Up)), C.int(core.RateLevel(rate.Down)))
}
func (*speedBar) hide() { C.speedBarHide() }

//export speedBarClicked
func speedBarClicked() {
	speedBarClick.Lock()
	handler := speedBarClick.handler
	speedBarClick.Unlock()
	if handler != nil {
		go handler()
	}
}
