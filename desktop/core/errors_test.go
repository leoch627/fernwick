package core

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorCodesSurviveWrapping(t *testing.T) {
	err := fmt.Errorf("operation: %w", NewAppError("STORAGE_LOCKED"))
	if CodeOf(err) != "STORAGE_LOCKED" {
		t.Fatal("lost typed error")
	}
	if CodeOf(errors.New("network failure")) != "CONTROL_UNAVAILABLE" {
		t.Fatal("incorrect unknown error mapping")
	}
	if NewAppError("INVALID_INPUT").Error() != "输入不符合要求" {
		t.Fatal("error message changed")
	}
}
