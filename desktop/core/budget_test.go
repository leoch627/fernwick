package core

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBudgetCancellationBoundaries(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	budget := NewBudget(time.Hour, parent)
	defer budget.Dispose()
	called := false
	err := budget.Run(func(context.Context) error { called = true; return nil })
	if called || CodeOf(err) != "CANCELLED" || budget.Remaining() != 0 {
		t.Fatalf("pre-cancelled budget ran callback: called=%v err=%v", called, err)
	}
	live := NewBudget(time.Hour, nil)
	defer live.Dispose()
	value, err := BudgetRun(live, func(context.Context) (string, error) {
		live.Cancel()
		return "stale result", errors.New("late transport failure")
	})
	if value != "" || CodeOf(err) != "CANCELLED" {
		t.Fatalf("post-cancelled callback escaped: %q %v", value, err)
	}
}

func TestBudgetDeadlineReachesIO(t *testing.T) {
	budget := NewBudget(5*time.Millisecond, nil)
	defer budget.Dispose()
	err := budget.Run(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if CodeOf(err) != "CANCELLED" {
		t.Fatalf("deadline error = %v", err)
	}
	parent, cancel := context.WithCancel(context.Background())
	child := NewBudget(time.Hour, parent)
	defer child.Dispose()
	cancel()
	if CodeOf(child.Check()) != "CANCELLED" {
		t.Fatal("parent cancellation did not reach child")
	}
}

func TestBudgetPreservesResultsAndErrors(t *testing.T) {
	budget := NewBudget(time.Hour, nil)
	defer budget.Dispose()
	value, err := BudgetRun(budget, func(context.Context) (int, error) { return 42, nil })
	if err != nil || value != 42 || budget.Remaining() <= 0 {
		t.Fatalf("valid operation = %d, %v", value, err)
	}
	want := errors.New("transport unavailable")
	if err := budget.Run(func(context.Context) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback error changed: %v", err)
	}
	budget.Dispose()
	if CodeOf(budget.Check()) != "CANCELLED" {
		t.Fatal("disposed budget remained usable")
	}
}
