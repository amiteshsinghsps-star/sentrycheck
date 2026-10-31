package probe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func configuration() Config {
	return Config{Node: "node1", Runtime: "gvisor", Version: "20260921.0", Architecture: "amd64", Handler: "runsc", Binary: "runsc", Crictl: "crictl", Endpoint: "unix:///test.sock", ExpectedRuntimeType: "io.containerd.runsc.v1"}
}
func fake(runtimeType string, missing, cleanupFail bool) Command {
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if name == "runsc" {
			if missing {
				return nil, errors.New("binary missing")
			}
			return []byte("runsc version release-20260921.0"), nil
		}
		if strings.Contains(joined, "runp") {
			return []byte("canary123"), nil
		}
		if strings.Contains(joined, "inspectp") {
			return []byte(`{"info":{"runtimeType":"` + runtimeType + `"},"status":{"id":"canary123","state":"SANDBOX_READY"}}`), nil
		}
		if cleanupFail {
			return nil, errors.New("cleanup failed")
		}
		return nil, nil
	}
}

func TestDeliberateMissingRuntimeIsLoud(t *testing.T) {
	report := Check(context.Background(), configuration(), fake("io.containerd.runsc.v1", true, false), time.Now())
	if report.Healthy || report.Verified || report.State != "runtime-unavailable" {
		t.Fatal(report)
	}
}

func TestKnownRuncTypeCannotBeConfiguredAsSandboxIsolation(t *testing.T) {
	for _, runtimeType := range []string{"runc", "io.containerd.runc.v1", "io.containerd.runc.v2", "io.containerd.runtime.v1.linux"} {
		cfg := configuration()
		cfg.ExpectedRuntimeType = runtimeType
		command := func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("invalid isolation configuration invoked a runtime command")
			return nil, nil
		}
		report := Check(context.Background(), cfg, command, time.Now())
		if report.Verified || report.Healthy || report.State != "invalid-configuration" {
			t.Fatal("known runc type was accepted as a sandbox", report)
		}
	}
}
func TestCRIWrongRuntimeDetectsIsolationMismatch(t *testing.T) {
	report := Check(context.Background(), configuration(), fake("io.containerd.runc.v2", false, false), time.Now())
	if report.Healthy || report.State != "isolation-mismatch" {
		t.Fatal(report)
	}
}
func TestBinaryAloneDoesNotAttestIsolation(t *testing.T) {
	cfg := configuration()
	cfg.SkipCanary = true
	report := Check(context.Background(), cfg, fake("io.containerd.runsc.v1", false, false), time.Now())
	if report.Healthy || report.Verified || report.State != "binary-present-unverified" {
		t.Fatal(report)
	}
}
func TestVerifiedCanaryAndCleanupFailure(t *testing.T) {
	report := Check(context.Background(), configuration(), fake("io.containerd.runsc.v1", false, false), time.Now())
	if !report.Healthy || !report.Verified {
		t.Fatal(report)
	}
	report = Check(context.Background(), configuration(), fake("io.containerd.runsc.v1", false, true), time.Now())
	if report.Healthy || report.State != "canary-cleanup-failed" {
		t.Fatal(report)
	}
}
func TestMissingRuntimeTypeStaysUnknown(t *testing.T) {
	report := Check(context.Background(), configuration(), fake("", false, false), time.Now())
	if report.Verified || report.State != "runtime-type-unavailable" {
		t.Fatal(report)
	}
}

func TestCanaryMustBeReadyAndMatchNewSandbox(t *testing.T) {
	cases := []struct {
		name, status, expected string
	}{
		{"not-ready", `{"id":"canary123","state":"SANDBOX_NOTREADY"}`, "canary-not-ready"},
		{"numeric-not-ready", `{"id":"canary123","state":1}`, "canary-not-ready"},
		{"state-missing", `{"id":"canary123"}`, "canary-not-ready"},
		{"null-state", `{"id":"canary123","state":null}`, "canary-not-ready"},
		{"different-sandbox", `{"id":"other","state":"SANDBOX_READY"}`, "canary-inspection-mismatch"},
		{"status-missing", `{}`, "canary-inspection-mismatch"},
		{"numeric-ready", `{"id":"canary123","state":0}`, "canary-verified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cleanup := 0
			fallback := fake("io.containerd.runsc.v1", false, false)
			command := func(ctx context.Context, name string, args ...string) ([]byte, error) {
				joined := strings.Join(args, " ")
				if strings.Contains(joined, "inspectp") {
					return []byte(`{"info":{"runtimeType":"io.containerd.runsc.v1"},"status":` + tc.status + `}`), nil
				}
				if strings.Contains(joined, "stopp") || strings.Contains(joined, "rmp") {
					cleanup++
				}
				return fallback(ctx, name, args...)
			}
			report := Check(context.Background(), configuration(), command, time.Now())
			if report.State != tc.expected || report.Healthy != (tc.expected == "canary-verified") || report.Verified != report.Healthy {
				t.Fatalf("unexpected readiness result: %+v", report)
			}
			if cleanup != 2 {
				t.Fatalf("sandbox cleanup did not run: %d calls", cleanup)
			}
		})
	}
}

func TestInvalidCanaryIDCannotBecomeCommandOption(t *testing.T) {
	fallback := fake("io.containerd.runsc.v1", false, false)
	command := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "runp") {
			return []byte("--help"), nil
		}
		if name != "runsc" {
			t.Fatal("invalid sandbox ID passed to another CRI command")
		}
		return fallback(ctx, name, args...)
	}
	report := Check(context.Background(), configuration(), command, time.Now())
	if report.State != "invalid-canary-id" || report.Healthy {
		t.Fatal(report)
	}
}

func TestProbeCommandOutputHelper(t *testing.T) {
	if os.Args[len(os.Args)-1] != "sentrycheck-output-limit-helper" {
		return
	}
	fmt.Print(strings.Repeat("x", 256*1024+1))
	os.Exit(0)
}

func TestCommandOutputLimitCannotSilentlySucceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := Execute(ctx, os.Args[0], "-test.run=^TestProbeCommandOutputHelper$", "--", "sentrycheck-output-limit-helper")
	if err == nil || !strings.Contains(err.Error(), "output exceeds") {
		t.Fatalf("oversized successful command was accepted: %v", err)
	}
	if len(output) > 256*1024 {
		t.Fatalf("retained output exceeds its bound: %d", len(output))
	}
}

func TestCleanupRetriesConcurrentStopRaceAndRetainsDiagnostics(t *testing.T) {
	calls := map[string]int{}
	command := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 21*time.Second {
			t.Fatal("cleanup command has no bounded deadline")
		}
		verb := args[4]
		calls[verb]++
		if verb == "rmp" && (args[5] != "--force" || args[6] != "canary123") {
			t.Fatal("force removal is not scoped to the created sandbox", args)
		}
		if calls[verb] == 1 {
			return []byte("rpc error: failed to kill pod sandbox container: ttrpc: closed"), errors.New("exit status 1")
		}
		return nil, nil
	}
	details, err := cleanupCanary(configuration(), command, "canary123")
	if err != nil || calls["stopp"] != 2 || calls["rmp"] != 2 {
		t.Fatal(calls, details, err)
	}
	if !strings.Contains(strings.Join(details, "\n"), "ttrpc: closed") || !strings.Contains(strings.Join(details, "\n"), "cleanup completed") {
		t.Fatal("cleanup diagnostics lost", details)
	}
}

func TestCleanupAlreadyRemovedRequiresSuccessfulAbsenceEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, list string
		ok         bool
	}{
		{"already-removed", `{"items":[]}`, true},
		{"invalid-list", `{}`, false},
		{"still-present", `{"items":[{"id":"canary123"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if args[4] == "stopp" {
					return nil, nil
				}
				if args[4] == "pods" {
					if args[5] != "--id" || args[6] != "canary123" {
						t.Fatal("absence query was not scoped to the canary", args)
					}
					return []byte(tc.list), nil
				}
				return []byte("sandbox status not found"), errors.New("exit status 1")
			}
			details, err := cleanupCanary(configuration(), command, "canary123")
			if (err == nil) != tc.ok {
				t.Fatal(details, err)
			}
		})
	}
}
