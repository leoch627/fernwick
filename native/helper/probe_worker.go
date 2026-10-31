package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// An unprivileged, parent-bound process for isolated SOCKS probes. It never invokes platform networking.
func probeWorker(parent string, check bool) error {
	pid, e := strconv.Atoi(parent)
	if e != nil || pid != os.Getppid() {
		return failure("PERMISSION_REQUIRED")
	}
	birth, e := processBirth(pid)
	if e != nil {
		return e
	}
	path, args, e := processIdentity(pid)
	if e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(self), "../../.."))
	if targetOS() == "darwin" {
		root = filepath.Dir(root)
	}
	if !samePath(path, expectedAppExecutable(root)) || !validAppArguments(args, path) {
		return failure("PERMISSION_REQUIRED")
	}
	data, e := io.ReadAll(io.LimitReader(os.Stdin, 2*1024*1024+1))
	if e != nil || len(data) > 2*1024*1024 {
		return failure("INVALID_INPUT")
	}
	var config struct {
		Log      json.RawMessage `json:"log"`
		Inbounds []struct {
			Tag      string `json:"tag"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Auth     string `json:"auth"`
				Accounts []struct {
					User string `json:"user"`
					Pass string `json:"pass"`
				} `json:"accounts"`
				UDP bool `json:"udp"`
			} `json:"settings"`
		} `json:"inbounds"`
		Outbounds []json.RawMessage `json:"outbounds"`
		Routing   json.RawMessage   `json:"routing"`
	}
	if strictJSON(data, &config) != nil || len(config.Inbounds) != 1 || len(config.Outbounds) != 1 {
		return failure("INVALID_INPUT")
	}
	in := config.Inbounds[0]
	if in.Protocol != "socks" || in.Listen != "127.0.0.1" || in.Port < 1024 || in.Port > 65535 || in.Settings.Auth != "password" || len(in.Settings.Accounts) != 1 || len(in.Settings.Accounts[0].Pass) < 16 || in.Settings.UDP {
		return failure("INVALID_INPUT")
	}
	var outbound struct {
		Protocol       string          `json:"protocol"`
		Tag            string          `json:"tag"`
		Settings       json.RawMessage `json:"settings"`
		StreamSettings json.RawMessage `json:"streamSettings"`
	}
	if strictJSON(config.Outbounds[0], &outbound) != nil || !contains([]string{"vless", "vmess", "trojan", "shadowsocks"}, outbound.Protocol) {
		return failure("INVALID_INPUT")
	}
	core := filepath.Join(filepath.Dir(self), filepath.Base(coreExecutable()))
	sum, e := digestFile(core)
	if e != nil || sum != build.CoreHashes[targetID()] {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	installed.CorePath = core
	parentContext, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()
	ctx, cancel := context.WithTimeout(parentContext, 15*time.Second)
	defer cancel()
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if current, e := processBirth(pid); e != nil || current != birth {
					cancel()
					return
				}
			}
		}
	}()
	arguments := []string{"run", "-format", "json", "-config", "stdin:"}
	if check {
		arguments = append(arguments, "-test")
	}
	command := exec.CommandContext(ctx, core, arguments...)
	command.Env = safeEnvironment()
	command.Dir = filepath.Dir(core)
	command.Stdin = bytes.NewReader(data)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	configureChild(command)
	if e = command.Start(); e != nil {
		return e
	}
	if e = attachCore(command); e != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return e
	}
	return command.Wait()
}
