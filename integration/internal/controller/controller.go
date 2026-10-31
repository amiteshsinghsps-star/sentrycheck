// Package controller materializes trusted report/health data for CEL policies.
package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sentrycheck.local/integration/internal/attest"
	"sentrycheck.local/integration/internal/kube"
	"sentrycheck.local/integration/internal/policy"
	"sentrycheck.local/integration/internal/probe"
	"sort"
	"strings"
	"time"
)

type RuntimeConfig struct {
	Name                string `json:"name"`
	Handler             string `json:"handler"`
	Runtime             string `json:"runtime"`
	Version             string `json:"version"`
	Architecture        string `json:"architecture"`
	ExpectedRuntimeType string `json:"expectedRuntimeType"`
	ManageScheduling    bool   `json:"manageScheduling"`
}

type Config struct {
	Namespace          string            `json:"namespace"`
	SnapshotName       string            `json:"snapshotName"`
	TrustedKeys        map[string]string `json:"trustedKeys"`
	Runtimes           []RuntimeConfig   `json:"runtimes"`
	MaxScanAgeSeconds  int64             `json:"maxScanAgeSeconds"`
	ProbeTTLSeconds    int64             `json:"probeTTLSeconds"`
	SnapshotTTLSeconds int64             `json:"snapshotTTLSeconds"`
}

type Node struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Unschedulable bool `json:"unschedulable"`
	} `json:"spec"`
	Status struct {
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
	} `json:"status"`
}

type RuntimeClass struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Handler    string `json:"handler"`
	Scheduling struct {
		NodeSelector map[string]string `json:"nodeSelector"`
	} `json:"scheduling"`
}

func LoadConfig(data []byte) (Config, error) {
	var cfg Config
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return cfg, fmt.Errorf("controller configuration must contain exactly one JSON object")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "sentrycheck-system"
	}
	if cfg.SnapshotName == "" {
		cfg.SnapshotName = "cluster"
	}
	if cfg.MaxScanAgeSeconds == 0 {
		cfg.MaxScanAgeSeconds = 86400
	}
	if cfg.ProbeTTLSeconds == 0 {
		cfg.ProbeTTLSeconds = 120
	}
	if cfg.SnapshotTTLSeconds == 0 {
		cfg.SnapshotTTLSeconds = 120
	}
	if cfg.MaxScanAgeSeconds < 60 || cfg.ProbeTTLSeconds < 10 || cfg.SnapshotTTLSeconds < 10 {
		return cfg, fmt.Errorf("freshness limits are too small")
	}
	for _, seconds := range []int64{cfg.MaxScanAgeSeconds, cfg.ProbeTTLSeconds, cfg.SnapshotTTLSeconds} {
		if seconds > math.MaxInt64/int64(time.Second) {
			return cfg, fmt.Errorf("freshness limit overflows a Go duration")
		}
	}
	seen := map[string]bool{}
	for _, runtime := range cfg.Runtimes {
		if runtime.Name == "" || runtime.Handler == "" || runtime.Version == "" || runtime.Architecture == "" || runtime.ExpectedRuntimeType == "" || seen[runtime.Name] {
			return cfg, fmt.Errorf("invalid or duplicate runtime configuration")
		}
		if runtime.Runtime != "gvisor" && runtime.Runtime != "kata" {
			return cfg, fmt.Errorf("runtime must be gvisor or kata")
		}
		if probe.KnownRuncRuntimeType(runtime.ExpectedRuntimeType) {
			return cfg, fmt.Errorf("RuntimeClass %s: a known runc runtime type cannot represent required gVisor/Kata isolation", runtime.Name)
		}
		seen[runtime.Name] = true
	}
	if len(cfg.Runtimes) == 0 {
		return cfg, fmt.Errorf("at least one managed RuntimeClass is required")
	}
	return cfg, nil
}

const healthSelectorPrefix = "sentrycheck.io.node-restriction.kubernetes.io/runtime-"

func Selector(runtime RuntimeConfig) (string, string) {
	hash := attest.Digest([]byte(strings.Join([]string{runtime.Name, runtime.Runtime, runtime.Version, runtime.Architecture, runtime.Handler, runtime.ExpectedRuntimeType}, "/")))
	return healthSelectorPrefix + hash[7:23], "verified"
}

func schedulingChanges(class RuntimeClass, runtime RuntimeConfig) map[string]any {
	key, value := Selector(runtime)
	changes := map[string]any{}
	for existing := range class.Scheduling.NodeSelector {
		if strings.HasPrefix(existing, healthSelectorPrefix) && existing != key {
			// JSON merge patch retains unspecified map keys. An obsolete health
			// selector would otherwise prevent newly added nodes from scheduling.
			changes[existing] = nil
		}
	}
	if class.Scheduling.NodeSelector[key] != value {
		changes[key] = value
	}
	if class.Scheduling.NodeSelector["kubernetes.io/arch"] != runtime.Architecture {
		changes["kubernetes.io/arch"] = runtime.Architecture
	}
	return changes
}

func Build(cfg Config, envelopes []attest.Envelope, probes []probe.Report, nodes []Node, classes []RuntimeClass, now time.Time) (policy.Snapshot, error) {
	snapshot := policy.Snapshot{GeneratedAt: now.UTC(), ExpiresAt: now.Add(time.Duration(cfg.SnapshotTTLSeconds) * time.Second).UTC(), Runtimes: []policy.RuntimeState{}, Images: []policy.ImageState{}, Warnings: []string{}}
	keys := map[string]ed25519.PublicKey{}
	for id, pem := range cfg.TrustedKeys {
		key, err := attest.PublicKey([]byte(pem))
		if err != nil {
			return snapshot, fmt.Errorf("trusted key %s: %w", id, err)
		}
		keys[id] = key
	}
	// Multiple signed reports are combined conservatively: any current hard failure
	// is retained, and every current claim must be complete to authorize a clean gate.
	images := map[string]policy.ImageState{}
	for _, envelope := range envelopes {
		claim, err := attest.Verify(envelope, keys, now, time.Duration(cfg.MaxScanAgeSeconds)*time.Second)
		if err != nil {
			snapshot.Warnings = append(snapshot.Warnings, "report rejected: "+err.Error())
			continue
		}
		// A snapshot must not outlive the evidence it incorporates. CEL cannot
		// read a clock, but offline evaluation and controller readiness can.
		for _, expiry := range []time.Time{claim.ExpiresAt, claim.ScannedAt.Add(time.Duration(cfg.MaxScanAgeSeconds) * time.Second)} {
			if expiry.Before(snapshot.ExpiresAt) {
				snapshot.ExpiresAt = expiry
			}
		}
		key := claim.ImageDigest + "/" + claim.Runtime.Name + "/" + claim.Runtime.Version + "/" + claim.Runtime.Architecture
		state := policy.ImageState{Digest: claim.ImageDigest, Runtime: claim.Runtime.Name, Version: claim.Runtime.Version, Architecture: claim.Runtime.Architecture,
			Complete: claim.Status == "complete" && claim.Provenance == "locally-executed" && claim.Coverage == "representative" && (claim.EvidenceTier == "dynamic-runsc-diff" || claim.EvidenceTier == "dynamic-kata-diff"), ReportDigest: claim.ReportDigest}
		for _, finding := range claim.Findings {
			if finding.Severity == "hard-failure" && (finding.EvidenceTier == "dynamic-runsc-diff" || finding.EvidenceTier == "dynamic-kata-diff") {
				state.HardFailure = true
			}
			if finding.Severity == "silent-degradation" {
				state.SilentDegradation = true
			}
		}
		if previous, ok := images[key]; ok {
			state.Complete = state.Complete && previous.Complete
			state.HardFailure = state.HardFailure || previous.HardFailure
			state.SilentDegradation = state.SilentDegradation || previous.SilentDegradation
		}
		images[key] = state
	}
	for _, state := range images {
		snapshot.Images = append(snapshot.Images, state)
	}
	sort.Slice(snapshot.Images, func(i, j int) bool {
		a, b := snapshot.Images[i], snapshot.Images[j]
		return a.Digest+a.Runtime+a.Version+a.Architecture < b.Digest+b.Runtime+b.Version+b.Architecture
	})
	for _, runtime := range cfg.Runtimes {
		selector, value := Selector(runtime)
		state := policy.RuntimeState{Name: runtime.Name, Handler: runtime.Handler, Runtime: runtime.Runtime, Version: runtime.Version, Architecture: runtime.Architecture, SelectorKey: selector, SelectorValue: value, HealthyNodes: []string{}}
		var configuredClass *RuntimeClass
		for i := range classes {
			class := &classes[i]
			if class.Metadata.Name == runtime.Name && class.Handler == runtime.Handler && class.Scheduling.NodeSelector[selector] == value && class.Scheduling.NodeSelector["kubernetes.io/arch"] == runtime.Architecture {
				state.Configured = true
				configuredClass = class
			}
		}
		if !state.Configured {
			snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("RuntimeClass %s is missing or its handler/health/architecture selectors differ from configuration", runtime.Name))
			snapshot.Runtimes = append(snapshot.Runtimes, state)
			continue
		}
		for _, node := range nodes {
			ready := false
			for _, condition := range node.Status.Conditions {
				if condition.Type == "Ready" && condition.Status == "True" {
					ready = true
				}
			}
			if !ready || node.Spec.Unschedulable || node.Metadata.Labels["kubernetes.io/arch"] != runtime.Architecture {
				continue
			}
			eligible := true
			for key, required := range configuredClass.Scheduling.NodeSelector {
				// The controller is about to reconcile its own health label;
				// all other RuntimeClass scheduling constraints must already hold.
				if key != selector && node.Metadata.Labels[key] != required {
					eligible = false
				}
			}
			if !eligible {
				continue
			}
			var newest *probe.Report
			conflicting := false
			for i := range probes {
				p := &probes[i]
				if p.Node != node.Metadata.Name || p.Runtime != runtime.Runtime || p.Handler != runtime.Handler || p.ExpectedVersion != runtime.Version || p.Architecture != runtime.Architecture {
					continue
				}
				if newest == nil || p.CheckedAt.After(newest.CheckedAt) {
					newest = p
					conflicting = false
				} else if p.CheckedAt.Equal(newest.CheckedAt) && (p.Schema != newest.Schema || p.Healthy != newest.Healthy || p.Verified != newest.Verified || p.ObservedVersion != newest.ObservedVersion || p.RuntimeType != newest.RuntimeType || p.State != newest.State || p.CanaryState != newest.CanaryState || p.CanaryID != newest.CanaryID) {
					conflicting = true
				}
			}
			if newest != nil && !conflicting && newest.Schema == "1.0" && newest.Healthy && newest.Verified && newest.State == "canary-verified" && newest.CanaryState == "SANDBOX_READY" && newest.CanaryID != "" && newest.ObservedVersion == runtime.Version && newest.RuntimeType == runtime.ExpectedRuntimeType && !newest.CheckedAt.After(now.Add(5*time.Second)) && now.Sub(newest.CheckedAt) <= time.Duration(cfg.ProbeTTLSeconds)*time.Second {
				state.HealthyNodes = append(state.HealthyNodes, node.Metadata.Name)
				if expiry := newest.CheckedAt.Add(time.Duration(cfg.ProbeTTLSeconds) * time.Second); expiry.Before(snapshot.ExpiresAt) {
					snapshot.ExpiresAt = expiry
				}
			}
			if conflicting {
				snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("RuntimeClass %s node %s has conflicting latest probe reports", runtime.Name, node.Metadata.Name))
			}
		}
		sort.Strings(state.HealthyNodes)
		snapshot.Runtimes = append(snapshot.Runtimes, state)
	}
	return snapshot, nil
}

func Reconcile(ctx context.Context, client *kube.Client, cfg Config, now time.Time) (policy.Snapshot, error) {
	var empty policy.Snapshot
	reportMaps, err := client.ConfigMaps(ctx, cfg.Namespace, "sentrycheck.io/type=report")
	if err != nil {
		return empty, err
	}
	probeMaps, err := client.ConfigMaps(ctx, cfg.Namespace, "sentrycheck.io/type=node-probe")
	if err != nil {
		return empty, err
	}
	var nodes struct {
		Items []Node `json:"items"`
	}
	if err = client.Request(ctx, http.MethodGet, "/api/v1/nodes", nil, &nodes); err != nil {
		return empty, err
	}
	var classes struct {
		Items []RuntimeClass `json:"items"`
	}
	if err = client.Request(ctx, http.MethodGet, "/apis/node.k8s.io/v1/runtimeclasses", nil, &classes); err != nil {
		return empty, err
	}
	var envelopes []attest.Envelope
	var probes []probe.Report
	var parseWarnings []string
	for _, item := range reportMaps {
		var envelope attest.Envelope
		if err = json.Unmarshal([]byte(item.Data["attestation.json"]), &envelope); err != nil {
			parseWarnings = append(parseWarnings, fmt.Sprintf("ConfigMap %s ignored: %v", item.Metadata.Name, err))
			continue
		}
		envelopes = append(envelopes, envelope)
	}
	for _, item := range probeMaps {
		var report probe.Report
		if err = json.Unmarshal([]byte(item.Data["report.json"]), &report); err != nil {
			parseWarnings = append(parseWarnings, fmt.Sprintf("ConfigMap %s ignored: %v", item.Metadata.Name, err))
			continue
		}
		probes = append(probes, report)
	}
	for _, runtime := range cfg.Runtimes {
		if !runtime.ManageScheduling {
			continue
		}
		for i := range classes.Items {
			class := &classes.Items[i]
			if class.Metadata.Name != runtime.Name {
				continue
			}
			if class.Handler != runtime.Handler {
				// Still publish the unhealthy state and remove health labels below.
				// Aborting here leaves the previously verified snapshot in effect.
				continue
			}
			changes := schedulingChanges(*class, runtime)
			if len(changes) > 0 {
				patch := map[string]any{"scheduling": map[string]any{"nodeSelector": changes}}
				if err = client.Request(ctx, http.MethodPatch, "/apis/node.k8s.io/v1/runtimeclasses/"+url.PathEscape(runtime.Name), patch, nil); err != nil {
					return empty, err
				}
				if class.Scheduling.NodeSelector == nil {
					class.Scheduling.NodeSelector = map[string]string{}
				}
				for key, value := range changes {
					if value == nil {
						delete(class.Scheduling.NodeSelector, key)
					} else {
						class.Scheduling.NodeSelector[key] = value.(string)
					}
				}
			}
		}
	}
	snapshot, err := Build(cfg, envelopes, probes, nodes.Items, classes.Items, now)
	if err != nil {
		return empty, err
	}
	snapshot.Warnings = append(snapshot.Warnings, parseWarnings...)
	for _, node := range nodes.Items {
		labels := map[string]any{}
		// Configuration changes must revoke prior versions/handlers as well as
		// update current labels; otherwise old Pods can retain stale selectors.
		for key := range node.Metadata.Labels {
			if strings.HasPrefix(key, healthSelectorPrefix) {
				labels[key] = nil
			}
		}
		for _, runtime := range snapshot.Runtimes {
			healthy := false
			for _, name := range runtime.HealthyNodes {
				if name == node.Metadata.Name {
					healthy = true
				}
			}
			if healthy {
				if node.Metadata.Labels[runtime.SelectorKey] != runtime.SelectorValue {
					labels[runtime.SelectorKey] = runtime.SelectorValue
				} else {
					delete(labels, runtime.SelectorKey)
				}
			} else if _, present := node.Metadata.Labels[runtime.SelectorKey]; present {
				labels[runtime.SelectorKey] = nil
			}
		}
		if len(labels) > 0 {
			if err = client.Request(ctx, http.MethodPatch, "/api/v1/nodes/"+url.PathEscape(node.Metadata.Name), map[string]any{"metadata": map[string]any{"labels": labels}}, nil); err != nil {
				return empty, err
			}
		}
	}
	object := map[string]any{"apiVersion": "sentrycheck.io/v1alpha1", "kind": "SandboxPolicySnapshot", "metadata": map[string]any{"name": cfg.SnapshotName}, "spec": snapshot}
	if err = client.Upsert(ctx, "/apis/sentrycheck.io/v1alpha1/sandboxpolicysnapshots", cfg.SnapshotName, object); err != nil {
		return empty, err
	}
	return snapshot, nil
}
