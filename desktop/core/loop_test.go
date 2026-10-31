package core

import (
	"sync"
	"testing"
)

func TestLoopRechecksGenerationAfterIO(t *testing.T) {
	var loop Loop
	generation, committed := 0, false
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	loop.Go(func() {
		defer close(done)
		observed := generation
		loop.Await(func() { close(started); <-finish })
		if observed == generation {
			committed = true
		}
	})
	<-started
	loop.Run(func() { generation++; close(finish) })
	<-done
	if committed {
		t.Fatal("superseded operation committed after an I/O boundary")
	}
}

func TestLoopSerializesConcurrentEntrypoints(t *testing.T) {
	var loop Loop
	var work sync.WaitGroup
	value := 0
	for range 100 {
		work.Add(1)
		loop.Go(func() { defer work.Done(); value++ })
	}
	work.Wait()
	loop.Run(func() {
		if value != 100 {
			t.Fatalf("lost updates: %d", value)
		}
	})
}
