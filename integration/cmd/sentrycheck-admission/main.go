package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sentrycheck.local/integration/internal/attest"
	"sentrycheck.local/integration/internal/controller"
	"sentrycheck.local/integration/internal/kube"
	"sentrycheck.local/integration/internal/policy"
	"sentrycheck.local/integration/internal/probe"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sentrycheck-admission:", err)
		os.Exit(2)
	}
}
func writeJSON(value any, path string) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if path == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "--help" {
		fmt.Println("sentrycheck-admission: keygen | attest | verify | evaluate | reconcile | controller\nUse a subcommand with --help for options. Admission uses signed reports and ValidatingAdmissionPolicy/CEL; no webhook is required.")
		return nil
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "keygen":
		private := flags.String("private", "ci-private.pem", "New private key file (never commit)")
		public := flags.String("public", "ci-public.pem", "New public key file")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		return attest.GenerateKeys(*private, *public)
	case "attest":
		reportPath := flags.String("report", "", "Original sentrycheck JSON report")
		keyPath := flags.String("key", "", "CI Ed25519 private PEM")
		keyID := flags.String("key-id", "ci", "Trusted key ID")
		ttl := flags.Duration("ttl", 24*time.Hour, "Attestation TTL, at most 7 days")
		output := flags.String("output", "", "Output file; default stdout")
		namespace := flags.String("configmap-namespace", "", "Emit a Kubernetes report ConfigMap instead of a bare envelope")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		data, err := attest.ReadFile(*reportPath, 128*1024*1024)
		if err != nil {
			return err
		}
		keyData, err := attest.ReadFile(*keyPath, 16384)
		if err != nil {
			return err
		}
		key, err := attest.PrivateKey(keyData)
		if err != nil {
			return err
		}
		envelope, err := attest.Sign(data, key, *keyID, time.Now(), *ttl)
		if err != nil {
			return err
		}
		if *namespace != "" {
			encoded, _ := json.Marshal(envelope)
			name := "report-" + attest.Digest(envelope.Payload)[7:39]
			return writeJSON(map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "immutable": true, "metadata": map[string]any{"name": name, "namespace": *namespace, "labels": map[string]string{"sentrycheck.io/type": "report"}}, "data": map[string]string{"attestation.json": string(encoded)}}, *output)
		}
		return writeJSON(envelope, *output)
	case "verify":
		file := flags.String("file", "", "Attestation envelope")
		reportFile := flags.String("report", "", "Also verify the exact original report bytes against the signed digest")
		keyFile := flags.String("public-key", "", "Public PEM")
		keyID := flags.String("key-id", "ci", "Trusted key ID")
		maxAge := flags.Duration("max-scan-age", 24*time.Hour, "Maximum age of the original scan")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		data, err := attest.ReadFile(*file, 256*1024)
		if err != nil {
			return err
		}
		var envelope attest.Envelope
		if err = json.Unmarshal(data, &envelope); err != nil {
			return err
		}
		pem, err := attest.ReadFile(*keyFile, 16384)
		if err != nil {
			return err
		}
		key, err := attest.PublicKey(pem)
		if err != nil {
			return err
		}
		claims, err := verifyOne(envelope, *keyID, key, time.Now(), *maxAge)
		if err != nil {
			return err
		}
		if *reportFile != "" {
			report, err := attest.ReadFile(*reportFile, 128*1024*1024)
			if err != nil {
				return err
			}
			if err = attest.VerifyReport(claims, report); err != nil {
				return err
			}
		}
		return writeJSON(claims, "")
	case "evaluate":
		podPath := flags.String("pod", "", "Pod JSON after RuntimeClass admission mutation")
		snapshotPath := flags.String("snapshot", "", "Snapshot spec JSON")
		configPath := flags.String("config", "", "Controller config; detects configured RuntimeClasses missing from the snapshot")
		strict := flags.Bool("strict", false, "Exit 1 for policy violations")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		data, err := attest.ReadFile(*podPath, 1024*1024)
		if err != nil {
			return err
		}
		pod, err := policy.DecodePod(data)
		if err != nil {
			return err
		}
		snapshotData, err := attest.ReadFile(*snapshotPath, 16*1024*1024)
		if err != nil {
			return err
		}
		var snapshot policy.Snapshot
		if err = json.Unmarshal(snapshotData, &snapshot); err != nil {
			return err
		}
		var managed []string
		if *configPath != "" {
			cfg, err := readConfig(*configPath)
			if err != nil {
				return err
			}
			for _, runtime := range cfg.Runtimes {
				managed = append(managed, runtime.Name)
			}
		} else {
			for _, runtime := range snapshot.Runtimes {
				managed = append(managed, runtime.Name)
			}
		}
		decision := policy.EvaluateManaged(pod, snapshot, managed, *strict, time.Now())
		if err = writeJSON(decision, ""); err != nil {
			return err
		}
		if !decision.Allowed {
			os.Exit(1)
		}
		return nil
	case "reconcile":
		configPath := flags.String("config", "", "Controller config JSON")
		statePath := flags.String("state", "", "Offline state bundle with reports/probes/nodes/runtimeClasses")
		output := flags.String("output", "", "Output snapshot JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := readConfig(*configPath)
		if err != nil {
			return err
		}
		data, err := attest.ReadFile(*statePath, 16*1024*1024)
		if err != nil {
			return err
		}
		var state struct {
			Reports []attest.Envelope         `json:"reports"`
			Probes  []probe.Report            `json:"probes"`
			Nodes   []controller.Node         `json:"nodes"`
			Classes []controller.RuntimeClass `json:"runtimeClasses"`
		}
		if err = json.Unmarshal(data, &state); err != nil {
			return err
		}
		snapshot, err := controller.Build(cfg, state.Reports, state.Probes, state.Nodes, state.Classes, time.Now())
		if err != nil {
			return err
		}
		return writeJSON(snapshot, *output)
	case "controller":
		configPath := flags.String("config", "/etc/sentrycheck/config.json", "Controller config")
		interval := flags.Duration("interval", 30*time.Second, "Reconciliation interval")
		once := flags.Bool("once", false, "Reconcile once and exit")
		listen := flags.String("listen", ":8080", "Health endpoint")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *interval < time.Second {
			return fmt.Errorf("interval must be at least one second")
		}
		cfg, err := readConfig(*configPath)
		if err != nil {
			return err
		}
		client, err := kube.InCluster()
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var lastSuccess atomic.Int64
		var snapshotExpiresAt atomic.Int64
		if !*once {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
			mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
				if time.Since(time.Unix(lastSuccess.Load(), 0)) > 2**interval || !time.Now().Before(time.Unix(0, snapshotExpiresAt.Load())) {
					http.Error(w, "snapshot reconciliation is stale", http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusOK)
			})
			server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			go func() {
				if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("health endpoint: %v", err)
					stop()
				}
			}()
			defer server.Close()
		}
		ticker := time.NewTicker(*interval)
		defer ticker.Stop()
		for {
			snapshot, err := controller.Reconcile(ctx, client, cfg, time.Now())
			if err != nil {
				log.Printf("RECONCILE FAILED: %v", err)
			} else {
				snapshotExpiresAt.Store(snapshot.ExpiresAt.UnixNano())
				lastSuccess.Store(time.Now().Unix())
				log.Printf("snapshot refreshed: %d runtimes, %d trusted image entries, %d warnings", len(snapshot.Runtimes), len(snapshot.Images), len(snapshot.Warnings))
			}
			if *once {
				return err
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	default:
		return fmt.Errorf("unknown command %s", args[0])
	}
}

func readConfig(path string) (controller.Config, error) {
	data, err := attest.ReadFile(path, 1024*1024)
	if err != nil {
		return controller.Config{}, err
	}
	return controller.LoadConfig(data)
}
