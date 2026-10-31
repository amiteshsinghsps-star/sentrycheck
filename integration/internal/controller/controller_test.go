package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentrycheck.local/integration/internal/kube"
	"sentrycheck.local/integration/internal/policy"
	"sentrycheck.local/integration/internal/probe"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(now time.Time) (Config, Node, RuntimeClass, probe.Report) {
	cfg := Config{SnapshotTTLSeconds: 120, ProbeTTLSeconds: 120, MaxScanAgeSeconds: 86400, Runtimes: []RuntimeConfig{{Name: "sandbox", Handler: "runsc", Runtime: "gvisor", Version: "20260921.0", Architecture: "amd64", ExpectedRuntimeType: "io.containerd.runsc.v1"}}}
	node := Node{}
	node.Metadata.Name = "node1"
	node.Metadata.Labels = map[string]string{"kubernetes.io/arch": "amd64"}
	node.Status.Conditions = append(node.Status.Conditions, struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	}{"Ready", "True"})
	key, value := Selector(cfg.Runtimes[0])
	class := RuntimeClass{}
	class.Metadata.Name = "sandbox"
	class.Handler = "runsc"
	class.Scheduling.NodeSelector = map[string]string{key: value, "kubernetes.io/arch": "amd64"}
	good := probe.Report{Schema: "1.0", Node: "node1", Runtime: "gvisor", ExpectedVersion: "20260921.0", ObservedVersion: "20260921.0", Architecture: "amd64", Handler: "runsc", RuntimeType: "io.containerd.runsc.v1", CheckedAt: now.Add(-30 * time.Second), Healthy: true, Verified: true, State: "canary-verified", CanaryState: "SANDBOX_READY", CanaryID: "canary123"}
	return cfg, node, class, good
}

func TestLatestProbeAndTTLControlSchedulingHealth(t *testing.T) {
	now := time.Now().UTC()
	cfg, node, class, good := fixture(now)
	build := func(reports []probe.Report) bool {
		snapshot, err := Build(cfg, nil, reports, []Node{node}, []RuntimeClass{class}, now)
		if err != nil {
			t.Fatal(err)
		}
		if !snapshot.Runtimes[0].Configured {
			t.Fatal("configured runtime lost")
		}
		return len(snapshot.Runtimes[0].HealthyNodes) > 0
	}
	if !build([]probe.Report{good}) {
		t.Fatal("fresh verified canary rejected")
	}
	bad := good
	bad.CheckedAt = now
	bad.Healthy = false
	bad.Verified = false
	bad.State = "runtime-unavailable"
	if build([]probe.Report{good, bad}) {
		t.Fatal("new failure hidden by older healthy report")
	}
	bad.CheckedAt = good.CheckedAt
	for _, reports := range [][]probe.Report{{good, bad}, {bad, good}} {
		if build(reports) {
			t.Fatal("conflicting same-time probes depended on list order")
		}
	}
	good.CheckedAt = now.Add(-5 * time.Minute)
	if build([]probe.Report{good}) {
		t.Fatal("stale health accepted")
	}
	good.CheckedAt = now
	good.RuntimeType = "io.containerd.runc.v2"
	if build([]probe.Report{good}) {
		t.Fatal("wrong isolation accepted")
	}
}

func TestHandlerDriftReconcilesToUnhealthyAndRemovesLabel(t *testing.T) {
	now := time.Now().UTC()
	cfg, node, class, good := fixture(now)
	cfg.Namespace = "sentrycheck-system"
	cfg.SnapshotName = "cluster"
	cfg.Runtimes[0].ManageScheduling = true
	key, value := Selector(cfg.Runtimes[0])
	node.Metadata.Labels[key] = value
	retiredKey := healthSelectorPrefix + "retired-version"
	node.Metadata.Labels[retiredKey] = value
	class.Handler = "runc"
	reportData, _ := json.Marshal(good)
	var labelRemoved, published atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/sentrycheck-system/configmaps":
			items := []any{}
			if r.URL.Query().Get("labelSelector") == "sentrycheck.io/type=node-probe" {
				items = append(items, map[string]any{"metadata": map[string]any{"name": "node-report"}, "data": map[string]string{"report.json": string(reportData)}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/nodes":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []Node{node}})
		case r.Method == http.MethodGet && r.URL.Path == "/apis/node.k8s.io/v1/runtimeclasses":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []RuntimeClass{class}})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/nodes/node1":
			var patch struct {
				Metadata struct {
					Labels map[string]any `json:"labels"`
				} `json:"metadata"`
			}
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
				t.Error(err)
			}
			label, present := patch.Metadata.Labels[key]
			retired, retiredPresent := patch.Metadata.Labels[retiredKey]
			labelRemoved.Store(present && label == nil && retiredPresent && retired == nil)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.Path == "/apis/sentrycheck.io/v1alpha1/sandboxpolicysnapshots/cluster":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && r.URL.Path == "/apis/sentrycheck.io/v1alpha1/sandboxpolicysnapshots":
			var object struct {
				Spec policy.Snapshot `json:"spec"`
			}
			if err := json.NewDecoder(r.Body).Decode(&object); err != nil {
				t.Error(err)
			}
			published.Store(len(object.Spec.Runtimes) == 1 && !object.Spec.Runtimes[0].Configured && len(object.Spec.Runtimes[0].HealthyNodes) == 0)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := &kube.Client{BaseURL: server.URL, HTTP: server.Client()}
	snapshot, err := Reconcile(context.Background(), client, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if !labelRemoved.Load() || !published.Load() || len(snapshot.Warnings) == 0 {
		t.Fatalf("handler drift left trusted state behind: removed=%v published=%v warnings=%v", labelRemoved.Load(), published.Load(), snapshot.Warnings)
	}
}

func TestConfigRejectsTrailingJSONAndOverflowingDurations(t *testing.T) {
	cfg, _, _, _ := fixture(time.Now())
	data, _ := json.Marshal(cfg)
	if _, err := LoadConfig(append(data, []byte(` {"namespace":"other"}`)...)); err == nil {
		t.Fatal("trailing configuration object ignored")
	}
	cfg.ProbeTTLSeconds = 9223372037
	data, _ = json.Marshal(cfg)
	if _, err := LoadConfig(data); err == nil {
		t.Fatal("overflowing probe TTL accepted")
	}
}

func TestConfigRejectsKnownRuncTypeForSandboxRuntime(t *testing.T) {
	for _, runtime := range []string{"gvisor", "kata"} {
		for _, runtimeType := range []string{"io.containerd.runc.v1", "io.containerd.runc.v2", "io.containerd.runtime.v1.linux"} {
			cfg, _, _, _ := fixture(time.Now())
			cfg.Runtimes[0].Runtime = runtime
			cfg.Runtimes[0].ExpectedRuntimeType = runtimeType
			data, _ := json.Marshal(cfg)
			if _, err := LoadConfig(data); err == nil {
				t.Fatal("known runc runtime type accepted for", runtime)
			}
		}
	}
}

func TestSnapshotCannotOutliveVerifiedProbe(t *testing.T) {
	now := time.Now().UTC()
	cfg, node, class, good := fixture(now)
	good.CheckedAt = now.Add(-119 * time.Second)
	snapshot, err := Build(cfg, nil, []probe.Report{good}, []Node{node}, []RuntimeClass{class}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Runtimes[0].HealthyNodes) != 1 || !snapshot.ExpiresAt.Equal(now.Add(time.Second)) {
		t.Fatalf("snapshot expiry outlived probe evidence: %+v", snapshot)
	}
}

func TestVersionUpgradeRemovesObsoleteOwnedSchedulingSelector(t *testing.T) {
	cfg, _, class, _ := fixture(time.Now())
	oldKey, _ := Selector(cfg.Runtimes[0])
	class.Scheduling.NodeSelector["workload-pool"] = "isolated"
	cfg.Runtimes[0].Version = "20260928.0"
	newKey, value := Selector(cfg.Runtimes[0])
	changes := schedulingChanges(class, cfg.Runtimes[0])
	if removed, present := changes[oldKey]; !present || removed != nil {
		t.Fatal("old version selector was not removed by JSON merge patch")
	}
	if changes[newKey] != value {
		t.Fatal("new version selector was not added")
	}
	if _, changed := changes["workload-pool"]; changed {
		t.Fatal("operator scheduling selector modified")
	}
}

func TestSelectorIsProtectedAndVersionSpecific(t *testing.T) {
	a := RuntimeConfig{Name: "sandbox", Runtime: "gvisor", Version: "1", Architecture: "amd64"}
	keyA, _ := Selector(a)
	a.Version = "2"
	keyB, _ := Selector(a)
	if keyA == keyB {
		t.Fatal("version drift reuses health label")
	}
	if !strings.HasPrefix(keyA, "sentrycheck.io.node-restriction.kubernetes.io/") {
		t.Fatal("health selector is not protected by NodeRestriction", keyA)
	}
}

func TestSelectorBindsHandlerAndRuntimeType(t *testing.T) {
	cfg, _, _, _ := fixture(time.Now())
	initial := cfg.Runtimes[0]
	key, _ := Selector(initial)
	for _, changed := range []RuntimeConfig{
		func() RuntimeConfig { r := initial; r.Handler = "runsc-other"; return r }(),
		func() RuntimeConfig { r := initial; r.ExpectedRuntimeType = "io.containerd.runsc.v2"; return r }(),
	} {
		if other, _ := Selector(changed); other == key {
			t.Fatal("runtime handler configuration reused a prior health label")
		}
	}
}

func TestHealthRequiresSchedulingEligibilityAndConsistentCanary(t *testing.T) {
	for _, failure := range []string{"operator-selector", "missing-canary", "not-ready", "failed-state"} {
		t.Run(failure, func(t *testing.T) {
			now := time.Now().UTC()
			cfg, node, class, good := fixture(now)
			switch failure {
			case "operator-selector":
				class.Scheduling.NodeSelector["workload-pool"] = "isolated"
			case "missing-canary":
				good.CanaryID = ""
			case "not-ready":
				good.CanaryState = "SANDBOX_NOTREADY"
			case "failed-state":
				good.State = "canary-cleanup-failed"
			}
			snapshot, err := Build(cfg, nil, []probe.Report{good}, []Node{node}, []RuntimeClass{class}, now)
			if err != nil || len(snapshot.Runtimes[0].HealthyNodes) != 0 {
				t.Fatalf("ineligible or contradictory probe accepted: %+v %v", snapshot, err)
			}
		})
	}
}
