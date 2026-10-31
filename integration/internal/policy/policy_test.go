package policy

import (
	"strings"
	"testing"
	"time"
)

func fixture() (Pod, Snapshot, time.Time) {
	now := time.Now().UTC()
	digest := "sha256:" + strings.Repeat("a", 64)
	pod := Pod{}
	pod.Spec.RuntimeClassName = "sandbox"
	pod.Spec.NodeSelector = map[string]string{"health": "yes", "kubernetes.io/arch": "amd64"}
	pod.Spec.Containers = []Container{{Name: "app", Image: "registry/app@" + digest}}
	snapshot := Snapshot{ExpiresAt: now.Add(time.Minute), Runtimes: []RuntimeState{{Name: "sandbox", Runtime: "gvisor", Version: "20260921.0", Architecture: "amd64", Configured: true, SelectorKey: "health", SelectorValue: "yes", HealthyNodes: []string{"node1"}}}, Images: []ImageState{{Digest: digest, Runtime: "gvisor", Version: "20260921.0", Architecture: "amd64", Complete: true}}}
	return pod, snapshot, now
}

func TestWarnOnlyAndStrictDigestBinding(t *testing.T) {
	pod, snapshot, now := fixture()
	if !Evaluate(pod, snapshot, true, now).Allowed {
		t.Fatal("healthy signed image rejected")
	}
	pod.Spec.Containers[0].Image = "registry/app:latest"
	if Evaluate(pod, snapshot, true, now).Allowed {
		t.Fatal("mutable tag accepted")
	}
	decision := Evaluate(pod, snapshot, false, now)
	if !decision.Allowed || len(decision.Warnings) == 0 {
		t.Fatal("warn-only rollout did not warn and allow")
	}
}

func TestInitEphemeralRuntimeDriftAndMissingHealth(t *testing.T) {
	for _, kind := range []string{"init", "ephemeral", "runtime", "health", "node", "stale", "hard-failure"} {
		t.Run(kind, func(t *testing.T) {
			pod, snapshot, now := fixture()
			switch kind {
			case "init":
				pod.Spec.InitContainers = []Container{{Name: "init", Image: "unscanned:tag"}}
			case "ephemeral":
				pod.Spec.EphemeralContainers = []Container{{Name: "debug", Image: "unscanned:tag"}}
			case "runtime":
				snapshot.Images[0].Version = "20260801.0"
			case "health":
				snapshot.Runtimes[0].HealthyNodes = nil
			case "node":
				pod.Spec.NodeName = "unverified-node"
			case "stale":
				snapshot.ExpiresAt = now.Add(-time.Minute)
			case "hard-failure":
				snapshot.Images[0].HardFailure = true
			}
			if Evaluate(pod, snapshot, true, now).Allowed {
				t.Fatal("unsafe case was accepted")
			}
		})
	}
}

func TestRequiredIsolationCannotOmitRuntimeClass(t *testing.T) {
	pod, snapshot, now := fixture()
	pod.Spec.RuntimeClassName = ""
	pod.Metadata.Labels = map[string]string{"sentrycheck.io/require-isolation": "true"}
	if Evaluate(pod, snapshot, true, now).Allowed {
		t.Fatal("required isolation silently omitted")
	}
}

func TestConfiguredRuntimeMustHaveExactlyOneSnapshotEntry(t *testing.T) {
	pod, snapshot, now := fixture()
	snapshot.Runtimes = nil
	if EvaluateManaged(pod, snapshot, []string{"sandbox"}, true, now).Allowed {
		t.Fatal("managed class absent from snapshot was allowed without an isolation label")
	}
	if !EvaluateManaged(pod, snapshot, []string{"different-class"}, true, now).Allowed {
		t.Fatal("unmanaged workload was unexpectedly intercepted")
	}
	pod, snapshot, now = fixture()
	snapshot.Images[0].HardFailure = true
	if !EvaluateManaged(pod, snapshot, []string{"different-class"}, true, now).Allowed {
		t.Fatal("retired RuntimeClass remaining in snapshot expanded the configured policy scope")
	}
	snapshot.Images[0].HardFailure = false
	snapshot.Runtimes = append(snapshot.Runtimes, snapshot.Runtimes[0])
	if EvaluateManaged(pod, snapshot, []string{"sandbox"}, true, now).Allowed {
		t.Fatal("duplicate RuntimeClass records were allowed")
	}
}
