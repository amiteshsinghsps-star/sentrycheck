package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleReport(now time.Time) []byte {
	native := map[string]any{"runtime": "runc", "exit_code": 0, "trace_summary": map[string]any{"event_count": 1}}
	sandbox := map[string]any{"runtime": "gvisor", "runtime_version": "20260921.0", "exit_code": 0, "trace_summary": map[string]any{"event_count": 1}}
	data, _ := json.Marshal(map[string]any{"schema_version": "1.0", "image_digest": "sha256:" + strings.Repeat("a", 64), "scanned_at": now, "target_runtime": Runtime{Name: "gvisor", Version: "20260921.0", Architecture: "amd64"}, "status": "complete", "assessment": "no-incompatibility-observed-in-profile", "findings": []Finding{}, "dynamic": map[string]any{"evidence_tier": "dynamic-runsc-diff", "provenance": "locally-executed", "profile_sha256": "sha256:" + strings.Repeat("b", 64), "profile": map[string]any{"coverage": "representative", "repetitions": 1}, "native": []any{native}, "sandbox": []any{sandbox}}})
	return data
}

func TestSignVerifyTamperingAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	envelope, err := Sign(sampleReport(now), priv, "ci", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"ci": pub}
	claims, err := Verify(envelope, keys, now, 24*time.Hour)
	if err != nil || claims.Runtime.Version != "20260921.0" {
		t.Fatal(claims, err)
	}
	if _, err = Verify(envelope, keys, now.Add(2*time.Hour), 24*time.Hour); err == nil {
		t.Fatal("expired attestation accepted")
	}
	if _, err = Verify(envelope, map[string]ed25519.PublicKey{}, now, 24*time.Hour); err == nil {
		t.Fatal("unknown key accepted")
	}
	envelope.Payload[10] ^= 1
	if _, err = Verify(envelope, keys, now, 24*time.Hour); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestFreshSignatureDoesNotRefreshOldEvidence(t *testing.T) {
	now := time.Now().UTC()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	envelope, err := Sign(sampleReport(now.Add(-48*time.Hour)), priv, "ci", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(envelope, map[string]ed25519.PublicKey{"ci": pub}, now, 24*time.Hour); err == nil {
		t.Fatal("old evidence renewed by a new signature")
	}
}

func TestImportedEvidenceCannotBecomeTrusted(t *testing.T) {
	now := time.Now().UTC()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := strings.ReplaceAll(string(sampleReport(now)), "locally-executed", "imported-user-supplied")
	if _, err := Sign([]byte(data), priv, "ci", now, time.Hour); err == nil {
		t.Fatal("imported evidence signed")
	}
}

func TestVerifiedReportMustMatchExactSignedBytes(t *testing.T) {
	now := time.Now().UTC()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	report := sampleReport(now)
	envelope, err := Sign(report, priv, "ci", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := Verify(envelope, map[string]ed25519.PublicKey{"ci": pub}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyReport(claims, report); err != nil {
		t.Fatal(err)
	}
	if err = VerifyReport(claims, append(report, '\n')); err == nil {
		t.Fatal("different report bytes accepted")
	}
}

func TestInvalidKeysAndFreshnessDoNotPanicOrAuthorize(t *testing.T) {
	now := time.Now().UTC()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Sign(sampleReport(now), nil, "ci", now, time.Hour); err == nil {
		t.Fatal("invalid private key accepted")
	}
	if _, err := Sign(sampleReport(now.Add(6*time.Minute)), priv, "ci", now, time.Hour); err == nil {
		t.Fatal("future-dated scan signed")
	}
	envelope, err := Sign(sampleReport(now), priv, "ci", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(envelope, map[string]ed25519.PublicKey{"ci": nil}, now, time.Hour); err == nil {
		t.Fatal("invalid public key accepted")
	}
	if _, err = Verify(envelope, map[string]ed25519.PublicKey{"ci": pub}, now, 0); err == nil {
		t.Fatal("zero scan age accepted")
	}
}

func TestReadFileLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path, 4); err == nil {
		t.Fatal("oversized file accepted")
	}
	if data, err := ReadFile(path, 5); err != nil || string(data) != "12345" {
		t.Fatal(string(data), err)
	}
	if _, err := ReadFile(path, -1); err == nil {
		t.Fatal("negative file limit accepted")
	}
}

func TestSignedClaimSemanticsCannotAuthorizeContradictoryEvidence(t *testing.T) {
	now := time.Now().UTC()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	envelope, err := Sign(sampleReport(now), priv, "ci", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"runtime-tier", "architecture", "profile-digest", "status", "severity", "hard-failure-tier", "complete-smoke"} {
		t.Run(bad, func(t *testing.T) {
			var claims Claims
			if err := json.Unmarshal(envelope.Payload, &claims); err != nil {
				t.Fatal(err)
			}
			switch bad {
			case "runtime-tier":
				claims.Runtime.Name = "kata"
			case "architecture":
				claims.Runtime.Architecture = "unknown"
			case "profile-digest":
				claims.ProfileDigest = "missing"
			case "status":
				claims.Status = "success"
			case "severity":
				claims.Findings = []Finding{{GapID: "gap", Severity: "hard_failure", EvidenceTier: "dynamic-runsc-diff"}}
			case "hard-failure-tier":
				claims.Findings = []Finding{{GapID: "gap", Severity: "hard-failure", EvidenceTier: "dynamic-native-only"}}
			case "complete-smoke":
				claims.Coverage = "smoke"
			}
			payload, _ := json.Marshal(claims)
			changed := envelope
			changed.Payload = payload
			changed.Signature = ed25519.Sign(priv, signingBytes(changed.KeyID, payload))
			if _, err := Verify(changed, map[string]ed25519.PublicKey{"ci": pub}, now, time.Hour); err == nil {
				t.Fatal("correct signature caused invalid evidence to be trusted")
			}
		})
	}
}

func TestCompleteReportsCannotHideDiscardedGuestRecords(t *testing.T) {
	now := time.Now().UTC()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, side := range []string{"native", "sandbox"} {
		for _, issue := range []string{"discarded_guest_records", "truncated", "infrastructure_error", "incomplete_reasons"} {
			t.Run(side+"-"+issue, func(t *testing.T) {
				var report map[string]any
				if err := json.Unmarshal(sampleReport(now), &report); err != nil {
					t.Fatal(err)
				}
				observation := report["dynamic"].(map[string]any)[side].([]any)[0].(map[string]any)
				trace := observation["trace_summary"].(map[string]any)
				trace["diagnostic_lines"] = 201
				switch issue {
				case "discarded_guest_records":
					trace[issue] = 1
				case "truncated":
					trace[issue] = true
				case "infrastructure_error":
					observation[issue] = "capture failed"
				case "incomplete_reasons":
					report[issue] = []string{"missing guest trace"}
				}
				report["dynamic"].(map[string]any)[side] = []any{observation}
				data, _ := json.Marshal(report)
				if _, err := Sign(data, priv, "ci", now, time.Hour); err == nil {
					t.Fatal("complete status hid incomplete capture evidence")
				}
			})
		}
	}
}

func TestCompleteClaimNeedsObservedSuccessfulBaseline(t *testing.T) {
	now := time.Now().UTC()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, issue := range []string{"missing", "baseline-failure", "wrong-version", "unfinished", "debug-only"} {
		t.Run(issue, func(t *testing.T) {
			var report map[string]any
			_ = json.Unmarshal(sampleReport(now), &report)
			dynamic := report["dynamic"].(map[string]any)
			native := dynamic["native"].([]any)[0].(map[string]any)
			sandbox := dynamic["sandbox"].([]any)[0].(map[string]any)
			switch issue {
			case "missing":
				dynamic["native"] = []any{}
			case "baseline-failure":
				native["exit_code"] = 42
			case "wrong-version":
				sandbox["runtime_version"] = "20260928.0"
			case "unfinished":
				native["trace_summary"].(map[string]any)["unfinished_count"] = 1
			case "debug-only":
				native["trace_summary"].(map[string]any)["diagnostic_lines"] = 201
			}
			data, _ := json.Marshal(report)
			_, err := Sign(data, priv, "ci", now, time.Hour)
			if (err == nil) != (issue == "debug-only") {
				t.Fatalf("wrong result for %s: %v", issue, err)
			}
		})
	}
}
