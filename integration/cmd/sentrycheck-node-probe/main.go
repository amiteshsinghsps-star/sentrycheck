package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sentrycheck.local/integration/internal/attest"
	"sentrycheck.local/integration/internal/kube"
	"sentrycheck.local/integration/internal/probe"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sentrycheck-node-probe:", err)
		os.Exit(2)
	}
}
func run() error {
	var cfg probe.Config
	flag.StringVar(&cfg.Node, "node", os.Getenv("NODE_NAME"), "Kubernetes node name")
	flag.StringVar(&cfg.Runtime, "runtime", "gvisor", "gvisor or kata")
	flag.StringVar(&cfg.Version, "version", "20260921.0", "Expected exact runtime version")
	flag.StringVar(&cfg.Architecture, "architecture", "amd64", "Node/image architecture")
	flag.StringVar(&cfg.Handler, "handler", "runsc", "CRI handler")
	flag.StringVar(&cfg.Binary, "binary", "/host/usr/local/bin/runsc", "Expected runtime binary on host mount")
	flag.StringVar(&cfg.Crictl, "crictl", "crictl", "Trusted crictl path")
	flag.StringVar(&cfg.Endpoint, "endpoint", "unix:///run/containerd/containerd.sock", "CRI endpoint")
	flag.StringVar(&cfg.ExpectedRuntimeType, "expected-runtime-type", "io.containerd.runsc.v1", "CRI runtimeType required for verified health")
	flag.BoolVar(&cfg.SkipCanary, "skip-canary", false, "Only inspect binary; always yields unverified health")
	publish := flag.Bool("publish", false, "Publish node report and Warning events in cluster")
	namespace := flag.String("namespace", "sentrycheck-system", "Controller namespace")
	interval := flag.Duration("interval", 60*time.Second, "Probe interval")
	once := flag.Bool("once", false, "Run once and exit; unhealthy/unverified returns 1")
	output := flag.String("output", "", "Also write report JSON to this file")
	flag.Parse()
	if *interval < time.Second {
		return fmt.Errorf("interval must be at least one second")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var client *kube.Client
	var err error
	if *publish {
		client, err = kube.InCluster()
		if err != nil {
			return err
		}
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	previous := ""
	for {
		report := probe.Check(ctx, cfg, probe.Execute, time.Now())
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		if *output != "" {
			if err = os.WriteFile(*output, append(data, '\n'), 0644); err != nil {
				return err
			}
		}
		if client != nil {
			name := "node-" + attest.Digest([]byte(cfg.Node + "/" + cfg.Runtime + "/" + cfg.Handler))[7:39]
			if err = client.PublishProbe(ctx, *namespace, name, report); err != nil {
				log.Printf("REPORT PUBLISH FAILED: %v", err)
				if *once {
					return err
				}
			}
			if !report.Healthy && previous != report.State {
				event := map[string]any{"apiVersion": "v1", "kind": "Event", "metadata": map[string]any{"generateName": "sentrycheck-runtime-", "namespace": *namespace}, "involvedObject": map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "name": name, "namespace": *namespace}, "related": map[string]any{"apiVersion": "v1", "kind": "Node", "name": cfg.Node}, "reason": "RuntimeIsolationUnverified", "message": fmt.Sprintf("SENTRYCHECK %s: %s handler %s is %s", cfg.Node, cfg.Runtime, cfg.Handler, report.State), "type": "Warning", "source": map[string]string{"component": "sentrycheck-node-probe"}, "firstTimestamp": time.Now().UTC().Format(time.RFC3339), "lastTimestamp": time.Now().UTC().Format(time.RFC3339), "count": 1}
				if err = client.Request(ctx, http.MethodPost, "/api/v1/namespaces/"+url.PathEscape(*namespace)+"/events", event, nil); err != nil {
					log.Printf("WARNING EVENT FAILED: %v", err)
				}
			}
		}
		previous = report.State
		if *once {
			if !report.Healthy {
				os.Exit(1)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
