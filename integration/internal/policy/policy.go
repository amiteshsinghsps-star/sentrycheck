// Package policy is the offline oracle for the shipped CEL admission policies.
package policy

import (
	"encoding/json"
	"fmt"
	"sentrycheck.local/integration/internal/attest"
	"strings"
	"time"
)

type RuntimeState struct {
	Name          string   `json:"name"`
	Handler       string   `json:"handler"`
	Runtime       string   `json:"runtime"`
	Version       string   `json:"version"`
	Architecture  string   `json:"architecture"`
	Configured    bool     `json:"configured"`
	SelectorKey   string   `json:"selectorKey"`
	SelectorValue string   `json:"selectorValue"`
	HealthyNodes  []string `json:"healthyNodes"`
}

type ImageState struct {
	Digest            string `json:"digest"`
	Runtime           string `json:"runtime"`
	Version           string `json:"version"`
	Architecture      string `json:"architecture"`
	Complete          bool   `json:"complete"`
	HardFailure       bool   `json:"hardFailure"`
	SilentDegradation bool   `json:"silentDegradation"`
	ReportDigest      string `json:"reportDigest"`
}

type Snapshot struct {
	GeneratedAt time.Time      `json:"generatedAt"`
	ExpiresAt   time.Time      `json:"expiresAt"`
	Runtimes    []RuntimeState `json:"runtimes"`
	Images      []ImageState   `json:"images"`
	Warnings    []string       `json:"warnings"`
}

type Pod struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		RuntimeClassName    string            `json:"runtimeClassName"`
		NodeName            string            `json:"nodeName"`
		NodeSelector        map[string]string `json:"nodeSelector"`
		Containers          []Container       `json:"containers"`
		InitContainers      []Container       `json:"initContainers"`
		EphemeralContainers []Container       `json:"ephemeralContainers"`
	} `json:"spec"`
}
type Container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}
type Decision struct {
	Allowed    bool     `json:"allowed"`
	Warnings   []string `json:"warnings"`
	Violations []string `json:"violations"`
}

func ImageDigest(image string) string {
	parts := strings.Split(image, "@")
	if len(parts) != 2 || parts[0] == "" || !attest.ValidDigest(parts[1]) {
		return ""
	}
	return parts[1]
}

func Evaluate(pod Pod, snapshot Snapshot, strict bool, now time.Time) Decision {
	managed := make([]string, 0, len(snapshot.Runtimes))
	for _, runtime := range snapshot.Runtimes {
		managed = append(managed, runtime.Name)
	}
	return EvaluateManaged(pod, snapshot, managed, strict, now)
}

// EvaluateManaged uses the same configured RuntimeClass names as the CEL match
// condition. Supplying them separately detects omitted entries in a snapshot.
// Evaluate alone can infer managed names only from the supplied snapshot.
func EvaluateManaged(pod Pod, snapshot Snapshot, managed []string, strict bool, now time.Time) Decision {
	decision := Decision{Allowed: true, Warnings: []string{}, Violations: []string{}}
	if !contains(managed, pod.Spec.RuntimeClassName) && pod.Metadata.Labels["sentrycheck.io/require-isolation"] != "true" {
		// Match the configured CEL policy scope, even if an old snapshot
		// still contains a RuntimeClass the operator no longer manages.
		return decision
	}
	var runtime *RuntimeState
	matches := 0
	for i := range snapshot.Runtimes {
		if snapshot.Runtimes[i].Name == pod.Spec.RuntimeClassName {
			runtime = &snapshot.Runtimes[i]
			matches++
		}
	}
	if matches > 1 {
		decision.Violations = append(decision.Violations, "controller snapshot has duplicate RuntimeClass entries")
	}
	if runtime == nil {
		if pod.Metadata.Labels["sentrycheck.io/require-isolation"] == "true" {
			decision.Violations = append(decision.Violations, "required isolation has no managed RuntimeClass")
		} else if contains(managed, pod.Spec.RuntimeClassName) {
			decision.Violations = append(decision.Violations, "configured managed RuntimeClass is missing from the controller snapshot")
		}
	} else {
		if !snapshot.ExpiresAt.After(now) {
			decision.Violations = append(decision.Violations, "controller snapshot is stale")
		}
		if !runtime.Configured || len(runtime.HealthyNodes) == 0 {
			decision.Violations = append(decision.Violations, "runtime handler has no verified healthy scheduling target")
		}
		if pod.Spec.NodeName != "" && !contains(runtime.HealthyNodes, pod.Spec.NodeName) {
			decision.Violations = append(decision.Violations, "direct node assignment bypasses verified runtime scheduling")
		}
		if pod.Spec.NodeSelector[runtime.SelectorKey] != runtime.SelectorValue || pod.Spec.NodeSelector["kubernetes.io/arch"] != runtime.Architecture {
			decision.Violations = append(decision.Violations, "RuntimeClass health/architecture selector is not present on the admitted Pod")
		}
		containers := append(append(append([]Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...), pod.Spec.EphemeralContainers...)
		for _, container := range containers {
			digest := ImageDigest(container.Image)
			if digest == "" {
				decision.Violations = append(decision.Violations, fmt.Sprintf("%s: image must use a scanned manifest digest", container.Name))
				continue
			}
			found := false
			for _, image := range snapshot.Images {
				if image.Digest != digest || image.Runtime != runtime.Runtime || image.Version != runtime.Version || image.Architecture != runtime.Architecture {
					continue
				}
				found = true
				if image.HardFailure {
					decision.Violations = append(decision.Violations, fmt.Sprintf("%s: confirmed hard-failure finding for target runtime", container.Name))
				}
				if !image.Complete {
					decision.Violations = append(decision.Violations, fmt.Sprintf("%s: report has incomplete evidence", container.Name))
				}
				if image.SilentDegradation {
					decision.Warnings = append(decision.Warnings, fmt.Sprintf("%s: report contains a silent-degradation finding", container.Name))
				}
			}
			if !found {
				decision.Violations = append(decision.Violations, fmt.Sprintf("%s: no trusted current report for this digest/runtime/version/architecture", container.Name))
			}
		}
	}
	decision.Warnings = append(decision.Warnings, decision.Violations...)
	decision.Allowed = !strict || len(decision.Violations) == 0
	return decision
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func DecodePod(data []byte) (Pod, error) { var p Pod; err := json.Unmarshal(data, &p); return p, err }
