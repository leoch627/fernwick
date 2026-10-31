package main

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

type UpdateRecovery struct {
	ID           string       `json:"id"`
	Pending      bool         `json:"pending"`
	WorkerPID    int          `json:"workerPid"`
	WorkerBirth  string       `json:"workerBirth"`
	Installation Installation `json:"installation"`
}

func updateRecoveryPath() string { return filepath.Join(stateRoot(), "update-recovery.json") }
func markUpdateApplying(job UpdateJob) error {
	birth, e := processBirth(os.Getpid())
	if e != nil {
		return e
	}
	return atomicJSON(updateRecoveryPath(), UpdateRecovery{ID: job.ID, Pending: true, WorkerPID: os.Getpid(), WorkerBirth: birth, Installation: installed})
}
func finishUpdateRecovery() error {
	var state UpdateRecovery
	if e := readJSON(updateRecoveryPath(), &state); e != nil {
		if os.IsNotExist(e) {
			return nil
		}
		return e
	}
	state.Pending = false
	return atomicJSON(updateRecoveryPath(), state)
}
func interruptedUpdate() (bool, error) {
	var state UpdateRecovery
	if e := readJSON(updateRecoveryPath(), &state); e != nil {
		if os.IsNotExist(e) {
			return false, nil
		}
		return false, e
	}
	if !state.Pending {
		return false, nil
	}
	if state.Installation.ProductID != build.ProductID || len(state.ID) != 48 || !regexpHex(state.ID) {
		return false, failure("UPDATE_VERIFY_FAILED")
	}
	if birth, e := processBirth(state.WorkerPID); e == nil && birth == state.WorkerBirth {
		return false, nil
	}
	// Service managers restart the service after this independent, unrestricted recovery worker exits.
	worker := filepath.Join(stateRoot(), "updates", "recovery-worker"+filepath.Ext(helperExecutable()))
	if e := copyFile(helperExecutable(), worker, 0700); e != nil {
		return false, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return true, launchRecoveryWorker(ctx, worker, state.ID)
}
func recoverInterruptedUpdate(id string) error {
	var state UpdateRecovery
	if e := readJSON(updateRecoveryPath(), &state); e != nil {
		return e
	}
	if !state.Pending || state.ID != id || state.Installation.ProductID != build.ProductID {
		return failure("UPDATE_VERIFY_FAILED")
	}
	state.WorkerPID = os.Getpid()
	state.WorkerBirth, _ = processBirth(os.Getpid())
	if e := atomicJSON(updateRecoveryPath(), state); e != nil {
		return e
	}
	installed = state.Installation
	if e := stopInstalledService(); e != nil {
		return e
	}
	if e := recoverAlone(); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if e := restorePlatformBackup(ctx); e != nil {
		return e
	}
	if e := finishUpdateRecovery(); e != nil {
		return e
	}
	return platformInstall(installed)
}
