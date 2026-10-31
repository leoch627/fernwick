package core

import (
	"context"
	"time"
)

// Budget propagates cancellation and bounds an operation with a monotonic
// deadline. Callers must pass Context() through to all blocking I/O.
type Budget struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewBudget(duration time.Duration, parent context.Context) *Budget {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, duration)
	return &Budget{ctx: ctx, cancel: cancel}
}

func (budget *Budget) Context() context.Context { return budget.ctx }
func (budget *Budget) Cancel()                  { budget.cancel() }

// Dispose releases the timer and cancels this budget. Unlike the old TS timer
// cleanup, it must only be called when every phase using the context is done.
func (budget *Budget) Dispose() { budget.cancel() }

func (budget *Budget) Remaining() time.Duration {
	if budget.ctx.Err() != nil {
		return 0
	}
	deadline, _ := budget.ctx.Deadline()
	return max(0, time.Until(deadline))
}

func (budget *Budget) Check() error {
	if budget.Remaining() <= 0 {
		return NewAppError("CANCELLED")
	}
	return nil
}

func (budget *Budget) Run(fn func(context.Context) error) error {
	_, err := BudgetRun(budget, func(ctx context.Context) (struct{}, error) { return struct{}{}, fn(ctx) })
	return err
}

// BudgetRun checks both sides of the I/O boundary so a result received after
// cancellation cannot be committed. The callback must cooperate with ctx.
func BudgetRun[T any](budget *Budget, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	if err := budget.Check(); err != nil {
		return zero, err
	}
	value, err := fn(budget.ctx)
	if cancelled := budget.Check(); cancelled != nil {
		return zero, cancelled
	}
	return value, err
}
