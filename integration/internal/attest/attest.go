// Package attest signs compact, digest-bound CI claims, not untrusted Pod annotations.
package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"time"
)

type Runtime struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

type Finding struct {
	GapID        string `json:"gap_id"`
	Severity     string `json:"severity"`
	EvidenceTier string `json:"evidence_tier"`
}

type Report struct {
	Schema            string    `json:"schema_version"`
	ImageDigest       string    `json:"image_digest"`
	ScannedAt         time.Time `json:"scanned_at"`
	Target            Runtime   `json:"target_runtime"`
	Status            string    `json:"status"`
	Assessment        string    `json:"assessment"`
	Findings          []Finding `json:"findings"`
	IncompleteReasons []string  `json:"incomplete_reasons"`
	Dynamic           *struct {
		EvidenceTier  string `json:"evidence_tier"`
		Provenance    string `json:"provenance"`
		ProfileDigest string `json:"profile_sha256"`
		Profile       struct {
			Coverage         string `json:"coverage"`
			Repetitions      int    `json:"repetitions"`
			ExpectedExitCode int    `json:"expected_exit_code"`
		} `json:"profile"`
		Native  []ReportObservation `json:"native"`
		Sandbox []ReportObservation `json:"sandbox"`
	} `json:"dynamic"`
}

type ReportObservation struct {
	Runtime        string `json:"runtime"`
	RuntimeVersion string `json:"runtime_version"`
	ExitCode       *int   `json:"exit_code"`
	TimedOut       bool   `json:"timed_out"`
	TraceSummary   struct {
		EventCount            uint64 `json:"event_count"`
		UnfinishedCount       uint64 `json:"unfinished_count"`
		DiscardedGuestRecords uint64 `json:"discarded_guest_records"`
		Truncated             bool   `json:"truncated"`
	} `json:"trace_summary"`
	InfrastructureError *string `json:"infrastructure_error"`
}

type Claims struct {
	Schema        string    `json:"schemaVersion"`
	ImageDigest   string    `json:"imageDigest"`
	Runtime       Runtime   `json:"runtime"`
	ScannedAt     time.Time `json:"scannedAt"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	Status        string    `json:"status"`
	Assessment    string    `json:"assessment"`
	EvidenceTier  string    `json:"evidenceTier"`
	Provenance    string    `json:"provenance"`
	Coverage      string    `json:"coverage"`
	ProfileDigest string    `json:"profileDigest"`
	ReportDigest  string    `json:"reportDigest"`
	Findings      []Finding `json:"findings"`
}

type Envelope struct {
	Schema    string `json:"schemaVersion"`
	KeyID     string `json:"keyId"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var keyPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,100}$`)

func ValidDigest(digest string) bool { return digestPattern.MatchString(digest) }
func Digest(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func ReadFile(path string, limit int64) ([]byte, error) {
	if limit < 0 || limit == math.MaxInt64 {
		return nil, errors.New("file size limit is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s must be a regular file at most %d bytes", path, limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is no longer a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s grew beyond the %d-byte limit", path, limit)
	}
	return data, nil
}

func GenerateKeys(privatePath, publicPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	privateFile, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer privateFile.Close()
	publicFile, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer publicFile.Close()
	if err = pem.Encode(privateFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}); err != nil {
		return err
	}
	return pem.Encode(publicFile, &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
}

func PrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("an Ed25519 key is required")
	}
	return key, nil
}

func PublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("an Ed25519 key is required")
	}
	return key, nil
}

func signingBytes(keyID string, payload []byte) []byte {
	return append([]byte("sentrycheck-attestation-v1\n"+keyID+"\n"), payload...)
}

// A valid signature authenticates bytes, but malformed or contradictory claim
// fields must still be rejected before they become admission policy inputs.
func validateClaims(claims Claims) error {
	if (claims.Runtime.Name != "gvisor" && claims.Runtime.Name != "kata") || claims.Runtime.Version == "" || claims.Runtime.Version == "unversioned" || (claims.Runtime.Architecture != "amd64" && claims.Runtime.Architecture != "arm64") {
		return errors.New("attestation runtime is unsupported or unpinned")
	}
	if claims.Status != "complete" && claims.Status != "incomplete" {
		return errors.New("attestation has an unknown report status")
	}
	switch claims.Assessment {
	case "no-incompatibility-observed-in-profile", "incompatibility-observed", "performance-regression-observed", "insufficient-evidence":
	default:
		return errors.New("attestation has an unknown assessment")
	}
	expectedDiff := "dynamic-runsc-diff"
	if claims.Runtime.Name == "kata" {
		expectedDiff = "dynamic-kata-diff"
	}
	if claims.EvidenceTier != "" {
		if claims.EvidenceTier != "dynamic-native-only" && claims.EvidenceTier != expectedDiff {
			return errors.New("attestation evidence tier does not match its target runtime")
		}
		if claims.Provenance != "locally-executed" || !ValidDigest(claims.ProfileDigest) || (claims.Coverage != "representative" && claims.Coverage != "smoke") {
			return errors.New("attestation lacks valid local execution/profile metadata")
		}
	} else if claims.Provenance != "" || claims.ProfileDigest != "" || claims.Coverage != "" {
		return errors.New("attestation has execution metadata without an evidence tier")
	}
	if claims.Status == "complete" && (claims.EvidenceTier != expectedDiff || claims.Coverage != "representative" || claims.Assessment == "insufficient-evidence") {
		return errors.New("complete attestation requires representative direct runtime comparison")
	}
	for _, finding := range claims.Findings {
		if finding.GapID == "" || (finding.EvidenceTier != "dynamic-native-only" && finding.EvidenceTier != expectedDiff) {
			return errors.New("finding lacks a gap ID or has inconsistent evidence tier")
		}
		switch finding.Severity {
		case "hard-failure", "silent-degradation", "performance-regression":
			if finding.EvidenceTier != expectedDiff || claims.EvidenceTier != expectedDiff {
				return errors.New("confirmed finding requires matching direct runtime evidence")
			}
		case "compatibility-risk":
		default:
			return errors.New("finding has an unknown severity")
		}
	}
	return nil
}

func Sign(reportData []byte, key ed25519.PrivateKey, keyID string, now time.Time, ttl time.Duration) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid Ed25519 private key size")
	}
	var report Report
	if err := json.Unmarshal(reportData, &report); err != nil {
		return Envelope{}, err
	}
	if !keyPattern.MatchString(keyID) || ttl <= 0 || ttl > 7*24*time.Hour {
		return Envelope{}, errors.New("valid key ID and TTL between 0 and 7 days required")
	}
	if report.Schema != "1.0" || !ValidDigest(report.ImageDigest) || report.ScannedAt.IsZero() {
		return Envelope{}, errors.New("report lacks schema, OCI digest, or scan timestamp")
	}
	if report.ScannedAt.After(now.Add(5 * time.Minute)) {
		return Envelope{}, errors.New("report scan timestamp is in the future")
	}
	if report.Target.Name != "gvisor" && report.Target.Name != "kata" {
		return Envelope{}, errors.New("unsupported report runtime")
	}
	if report.Target.Version == "" || report.Target.Version == "unversioned" || report.Target.Architecture == "" {
		return Envelope{}, errors.New("report runtime must be versioned and architecture-specific")
	}
	if report.Dynamic != nil && report.Dynamic.Provenance != "locally-executed" {
		return Envelope{}, errors.New("refusing to sign imported execution as trusted CI evidence")
	}
	claims := Claims{Schema: "1.0", ImageDigest: report.ImageDigest, Runtime: report.Target, ScannedAt: report.ScannedAt, IssuedAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC(), Status: report.Status, Assessment: report.Assessment, ReportDigest: Digest(reportData), Findings: report.Findings}
	if report.Dynamic != nil {
		claims.EvidenceTier = report.Dynamic.EvidenceTier
		claims.Provenance = report.Dynamic.Provenance
		claims.Coverage = report.Dynamic.Profile.Coverage
		claims.ProfileDigest = report.Dynamic.ProfileDigest
	}
	if err := validateClaims(claims); err != nil {
		return Envelope{}, err
	}
	if report.Status == "complete" {
		if len(report.IncompleteReasons) != 0 {
			return Envelope{}, errors.New("complete report contains incomplete reasons")
		}
		if report.Dynamic.Profile.Repetitions <= 0 || len(report.Dynamic.Native) != report.Dynamic.Profile.Repetitions || len(report.Dynamic.Sandbox) != report.Dynamic.Profile.Repetitions {
			return Envelope{}, errors.New("complete report lacks the requested native/sandbox observations")
		}
		for side, observations := range [][]ReportObservation{report.Dynamic.Native, report.Dynamic.Sandbox} {
			for _, observation := range observations {
				if observation.TraceSummary.EventCount == 0 || observation.TraceSummary.UnfinishedCount != 0 || observation.TraceSummary.DiscardedGuestRecords != 0 || observation.TraceSummary.Truncated || observation.InfrastructureError != nil {
					return Envelope{}, errors.New("complete report contains lost guest records or an incomplete observation")
				}
				if side == 0 && (observation.Runtime != "runc" || observation.ExitCode == nil || *observation.ExitCode != report.Dynamic.Profile.ExpectedExitCode || observation.TimedOut) {
					return Envelope{}, errors.New("complete report lacks a successful native workload baseline")
				}
				if side == 1 && (observation.Runtime != report.Target.Name || observation.RuntimeVersion != report.Target.Version) {
					return Envelope{}, errors.New("complete report observation does not match the pinned target runtime")
				}
			}
		}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return Envelope{}, err
	}
	if len(payload) > 128*1024 {
		return Envelope{}, errors.New("attestation claims exceed size limit")
	}
	return Envelope{Schema: "1.0", KeyID: keyID, Payload: payload, Signature: ed25519.Sign(key, signingBytes(keyID, payload))}, nil
}

func Verify(envelope Envelope, keys map[string]ed25519.PublicKey, now time.Time, maxScanAge time.Duration) (Claims, error) {
	var claims Claims
	if maxScanAge <= 0 {
		return claims, errors.New("maximum scan age must be positive")
	}
	key, ok := keys[envelope.KeyID]
	if envelope.Schema != "1.0" || !ok || len(key) != ed25519.PublicKeySize || !keyPattern.MatchString(envelope.KeyID) || len(envelope.Payload) > 128*1024 || !ed25519.Verify(key, signingBytes(envelope.KeyID, envelope.Payload), envelope.Signature) {
		return claims, errors.New("invalid or untrusted attestation signature")
	}
	if err := json.Unmarshal(envelope.Payload, &claims); err != nil {
		return claims, err
	}
	if claims.Schema != "1.0" || !ValidDigest(claims.ImageDigest) || !ValidDigest(claims.ReportDigest) {
		return claims, errors.New("invalid attestation digest/schema")
	}
	if !claims.ExpiresAt.After(now) || claims.IssuedAt.After(now.Add(5*time.Minute)) || !claims.ExpiresAt.After(claims.IssuedAt) || claims.ExpiresAt.Sub(claims.IssuedAt) > 7*24*time.Hour {
		return claims, errors.New("attestation expired or has invalid issuance time")
	}
	if claims.ScannedAt.IsZero() || claims.ScannedAt.After(claims.IssuedAt.Add(5*time.Minute)) || claims.ScannedAt.After(now.Add(5*time.Minute)) || now.Sub(claims.ScannedAt) > maxScanAge {
		return claims, errors.New("scan evidence is stale or future-dated")
	}
	if err := validateClaims(claims); err != nil {
		return claims, err
	}
	return claims, nil
}

// VerifyReport binds an already verified claim to the exact original report
// bytes. Reformatting JSON changes the digest and is deliberately rejected.
func VerifyReport(claims Claims, reportData []byte) error {
	if !ValidDigest(claims.ReportDigest) || claims.ReportDigest != Digest(reportData) {
		return errors.New("report bytes do not match the signed report digest")
	}
	return nil
}
