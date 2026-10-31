// Package probe verifies binary health and a CRI canary's reported runtime type.
// A binary-presence result is deliberately never promoted to verified isolation.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Node                string `json:"node"`
	Runtime             string `json:"runtime"`
	Version             string `json:"version"`
	Architecture        string `json:"architecture"`
	Handler             string `json:"handler"`
	Binary              string `json:"binary"`
	Crictl              string `json:"crictl"`
	Endpoint            string `json:"endpoint"`
	ExpectedRuntimeType string `json:"expectedRuntimeType"`
	SkipCanary          bool   `json:"skipCanary"`
}

type Report struct {
	Schema          string    `json:"schemaVersion"`
	Node            string    `json:"node"`
	Runtime         string    `json:"runtime"`
	ExpectedVersion string    `json:"expectedVersion"`
	ObservedVersion string    `json:"observedVersion"`
	Architecture    string    `json:"architecture"`
	Handler         string    `json:"handler"`
	RuntimeType     string    `json:"runtimeType"`
	CanaryID        string    `json:"canaryID,omitempty"`
	CanaryState     string    `json:"canaryState,omitempty"`
	CheckedAt       time.Time `json:"checkedAt"`
	Healthy         bool      `json:"healthy"`
	Verified        bool      `json:"verified"`
	State           string    `json:"state"`
	Details         []string  `json:"details"`
}

type Command func(context.Context, string, ...string) ([]byte, error)

// KnownRuncRuntimeType rejects an explicit contradiction of a gVisor/Kata
// isolation claim. Unknown custom shim types remain an operator trust input.
func KnownRuncRuntimeType(runtimeType string) bool {
	return runtimeType == "runc" || runtimeType == "io.containerd.runtime.v1.linux" || strings.HasPrefix(runtimeType, "io.containerd.runc.")
}

func diagnostic(err error, output []byte) string {
	message := strings.TrimSpace(string(output))
	if len(message) > 2048 {
		message = message[:2048] + " (truncated)"
	}
	if message == "" {
		return err.Error()
	}
	return err.Error() + ": " + message
}

type boundedOutput struct {
	// Do not embed bytes.Buffer: its promoted ReadFrom method allows io.Copy
	// in os/exec to bypass Write and the output bound.
	buffer    bytes.Buffer
	truncated bool
}

func (w *boundedOutput) Write(data []byte) (int, error) {
	original := len(data)
	remaining := 256*1024 - w.buffer.Len()
	if len(data) > remaining {
		w.truncated = true
	}
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = w.buffer.Write(data)
	}
	return original, nil
}
func Execute(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	// A descendant retaining stdout/stderr must not defeat the command timeout.
	command.WaitDelay = 2 * time.Second
	var output, diagnostic boundedOutput
	command.Stdout = &output
	command.Stderr = &diagnostic
	err := command.Run()
	if err == nil && (output.truncated || diagnostic.truncated) {
		err = fmt.Errorf("command output exceeds the 256 KiB per-stream limit")
	}
	if err != nil {
		return append(output.buffer.Bytes(), diagnostic.buffer.Bytes()...), err
	}
	return output.buffer.Bytes(), err
}

func cleanupCanary(cfg Config, command Command, id string) ([]string, error) {
	// CRI explicitly permits concurrent/idempotent StopPodSandbox calls. The
	// kubelet can reclaim this unmanaged canary while our first stop is in
	// progress, so retry boundedly and retain the original diagnostics.
	// https://github.com/kubernetes/cri-api/blob/v0.35.0/pkg/apis/runtime/v1/api.proto
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	base := []string{"--runtime-endpoint", cfg.Endpoint, "--timeout", "15s"}
	call := func(args ...string) ([]byte, error) {
		callCtx, callCancel := context.WithTimeout(ctx, 20*time.Second)
		defer callCancel()
		return command(callCtx, cfg.Crictl, append(append([]string{}, base...), args...)...)
	}
	details := []string{}
	var removeErr error
	for _, verb := range []string{"stopp", "rmp"} {
		var err error
		for attempt := 1; attempt <= 3; attempt++ {
			if ctx.Err() != nil {
				err = ctx.Err()
				break
			}
			args := []string{verb, id}
			if verb == "rmp" {
				// Limit force removal to the exact ID we just created. crictl
				// otherwise rejects a cached READY state without calling CRI.
				args = []string{verb, "--force", id}
			}
			var output []byte
			output, err = call(args...)
			if err == nil {
				break
			}
			details = append(details, fmt.Sprintf("canary %s attempt %d failed: %s", verb, attempt, diagnostic(err, output)))
			if attempt < 3 {
				timer := time.NewTimer(time.Duration(attempt) * 500 * time.Millisecond)
				select {
				case <-ctx.Done():
				case <-timer.C:
				}
				timer.Stop()
			}
		}
		if verb == "rmp" {
			removeErr = err
		}
	}
	if removeErr == nil {
		// CRI RemovePodSandbox itself must terminate and reclaim the sandbox;
		// a successful remove resolves an earlier transient stop failure.
		if len(details) > 0 {
			details = append(details, "canary cleanup completed after transient errors")
		}
		return details, nil
	}
	if ctx.Err() == nil {
		// crictl rmp requests status first and can fail NotFound if kubelet
		// already removed the sandbox. Confirm absence via a successful list;
		// never infer cleanup from an error message or unavailable CRI service.
		output, err := call("pods", "--id", id, "-o", "json")
		if err == nil {
			var list struct {
				Items *[]struct {
					ID string `json:"id"`
				} `json:"items"`
			}
			if json.Unmarshal(output, &list) == nil && list.Items != nil {
				absent := true
				for _, sandbox := range *list.Items {
					if sandbox.ID == "" || sandbox.ID == id {
						absent = false
					}
				}
				if absent {
					details = append(details, "CRI list confirmed the canary is already absent after cleanup errors")
					return details, nil
				}
			}
		} else {
			details = append(details, "could not confirm canary absence: "+diagnostic(err, output))
		}
	}
	return details, fmt.Errorf("canary removal was not confirmed within the bounded cleanup attempts: %w", removeErr)
}

func Check(ctx context.Context, cfg Config, command Command, now time.Time) (report Report) {
	report = Report{Schema: "1.0", Node: cfg.Node, Runtime: cfg.Runtime, ExpectedVersion: cfg.Version, Architecture: cfg.Architecture, Handler: cfg.Handler, CheckedAt: now.UTC(), State: "unverified", Details: []string{}}
	if KnownRuncRuntimeType(cfg.ExpectedRuntimeType) {
		report.State = "invalid-configuration"
		report.Details = append(report.Details, "a known runc runtime type cannot represent required gVisor/Kata isolation")
		return report
	}
	if cfg.Node == "" || cfg.Handler == "" || cfg.Version == "" || cfg.Version == "unversioned" || cfg.ExpectedRuntimeType == "" || cfg.Binary == "" || (cfg.Runtime != "gvisor" && cfg.Runtime != "kata") || (cfg.Architecture != "amd64" && cfg.Architecture != "arm64") || (!cfg.SkipCanary && (cfg.Crictl == "" || cfg.Endpoint == "")) {
		report.State = "invalid-configuration"
		report.Details = append(report.Details, "node, handler, pinned version, runtime (gvisor/kata), architecture (amd64/arm64), binary, and expected CRI runtime type are required; canaries also require crictl and an endpoint")
		return report
	}
	versionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	output, err := command(versionCtx, cfg.Binary, "--version")
	cancel()
	if err != nil {
		report.State = "runtime-unavailable"
		report.Details = append(report.Details, "runtime binary health check failed: "+diagnostic(err, output))
		return report
	}
	for _, word := range strings.Fields(string(output)) {
		if strings.TrimPrefix(word, "release-") == cfg.Version {
			report.ObservedVersion = cfg.Version
			break
		}
	}
	if report.ObservedVersion == "" {
		report.State = "version-mismatch"
		report.Details = append(report.Details, "installed binary did not report the required exact release")
		return report
	}
	if cfg.SkipCanary {
		report.State = "binary-present-unverified"
		report.Details = append(report.Details, "binary presence/version does not attest the selected CRI handler")
		return report
	}
	directory, err := os.MkdirTemp("", "sentrycheck-canary-")
	if err != nil {
		report.Details = append(report.Details, err.Error())
		return report
	}
	defer os.RemoveAll(directory)
	configPath := filepath.Join(directory, "pod.json")
	canary := map[string]any{"metadata": map[string]any{"name": "sentrycheck-runtime-canary", "namespace": "sentrycheck-system", "uid": fmt.Sprintf("sentrycheck-%d", now.UnixNano()), "attempt": 0}, "log_directory": directory, "linux": map[string]any{"security_context": map[string]any{}}}
	data, _ := json.Marshal(canary)
	if err = os.WriteFile(configPath, data, 0600); err != nil {
		report.Details = append(report.Details, err.Error())
		return report
	}
	base := []string{"--runtime-endpoint", cfg.Endpoint, "--timeout", "15s"}
	call := func(args ...string) ([]byte, error) {
		callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		return command(callCtx, cfg.Crictl, append(append([]string{}, base...), args...)...)
	}
	output, err = call("runp", "--runtime", cfg.Handler, configPath)
	if err != nil {
		report.State = "handler-canary-failed"
		report.Details = append(report.Details, "CRI failed to launch the requested handler: "+diagnostic(err, output))
		return report
	}
	id := strings.TrimSpace(string(output))
	if id == "" || strings.HasPrefix(id, "-") || strings.ContainsAny(id, " \n\r\t/\\\x00") || len(id) > 256 {
		report.State = "invalid-canary-id"
		return report
	}
	report.CanaryID = id
	defer func() {
		// Cleanup must survive caller cancellation. Never leave a canary running silently.
		details, cleanupErr := cleanupCanary(cfg, command, id)
		report.Details = append(report.Details, details...)
		if cleanupErr != nil {
			report.Healthy = false
			report.Verified = false
			report.State = "canary-cleanup-failed"
			report.Details = append(report.Details, cleanupErr.Error())
		}
	}()
	output, err = call("inspectp", "-o", "json", id)
	if err != nil {
		report.State = "canary-inspection-failed"
		report.Details = append(report.Details, diagnostic(err, output))
		return report
	}
	var inspection struct {
		Info   map[string]json.RawMessage `json:"info"`
		Status struct {
			ID    string          `json:"id"`
			State json.RawMessage `json:"state"`
		} `json:"status"`
	}
	if err = json.Unmarshal(output, &inspection); err != nil {
		report.State = "canary-inspection-invalid"
		report.Details = append(report.Details, err.Error())
		return report
	}
	if raw, ok := inspection.Info["runtimeType"]; ok {
		_ = json.Unmarshal(raw, &report.RuntimeType)
	}
	if report.RuntimeType == "" {
		report.State = "runtime-type-unavailable"
		report.Details = append(report.Details, "CRI did not expose runtimeType; absence is not a successful isolation check")
		return report
	}
	if report.RuntimeType != cfg.ExpectedRuntimeType {
		report.State = "isolation-mismatch"
		report.Details = append(report.Details, fmt.Sprintf("requested %s but CRI reports %s", cfg.ExpectedRuntimeType, report.RuntimeType))
		return report
	}
	if inspection.Status.ID != id {
		report.State = "canary-inspection-mismatch"
		report.Details = append(report.Details, "CRI inspection did not identify the newly created sandbox")
		return report
	}
	// CRI PodSandboxState READY is enum value 0. Proto JSON permits the
	// symbolic name and numeric enum value; an absent field is not evidence.
	// https://github.com/kubernetes/cri-api/blob/v0.35.0/pkg/apis/runtime/v1/api.proto
	state := strings.TrimSpace(string(inspection.Status.State))
	if state != `"SANDBOX_READY"` && state != "0" {
		report.State = "canary-not-ready"
		report.CanaryState = "unknown-or-not-ready"
		report.Details = append(report.Details, "CRI did not report SANDBOX_READY for the newly created sandbox")
		return report
	}
	report.CanaryState = "SANDBOX_READY"
	report.Healthy = true
	report.Verified = true
	report.State = "canary-verified"
	report.Details = append(report.Details, "Fresh CRI canary reported the configured runtime type; this is a point-in-time check, not cryptographic node attestation or proof about every existing Pod.")
	return report
}
