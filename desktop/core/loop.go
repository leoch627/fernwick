package core

import "sync"

// Loop serializes controller state between I/O boundaries, matching the old
// event loop. All entry points use Run or Go. Await must only be called inside
// such an entry point; callbacks passed to Await must not access controller state.
// After Await, callers must recheck their generation before committing results.
type Loop struct{ mu sync.Mutex }

func (loop *Loop) Run(fn func()) {
	loop.mu.Lock()
	defer loop.mu.Unlock()
	fn()
}

func (loop *Loop) Await(fn func()) {
	loop.mu.Unlock()
	defer loop.mu.Lock()
	fn()
}

func (loop *Loop) Go(fn func()) { go loop.Run(fn) }
