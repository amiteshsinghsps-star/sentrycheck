// Package kube provides the small Kubernetes REST surface needed by the controller.
// TLS verification and rotating in-cluster credentials stay enabled.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	BaseURL   string
	TokenFile string
	HTTP      *http.Client
}
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("Kubernetes HTTP %d: %s", e.Code, e.Message) }
func IsNotFound(err error) bool {
	var status *StatusError
	return errors.As(err, &status) && status.Code == 404
}

func InCluster() (*Client, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = "443"
	}
	if host == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST is unset; use reconcile/evaluate for offline operation")
	}
	credentials := os.Getenv("SENTRYCHECK_SERVICE_ACCOUNT_DIR")
	if credentials == "" {
		credentials = "/var/run/secrets/kubernetes.io/serviceaccount"
	}
	ca, err := os.ReadFile(filepath.Join(credentials, "ca.crt"))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid Kubernetes CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	return &Client{BaseURL: "https://" + net.JoinHostPort(host, port), TokenFile: filepath.Join(credentials, "token"), HTTP: &http.Client{Transport: transport, Timeout: 30 * time.Second}}, nil
}

func (c *Client) Request(ctx context.Context, method, path string, body any, out any) error {
	if !strings.HasPrefix(path, "/") {
		return errors.New("Kubernetes path must be absolute")
	}
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		if method == http.MethodPatch {
			request.Header.Set("Content-Type", "application/merge-patch+json")
		}
	}
	if c.TokenFile != "" {
		token, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseData, err := io.ReadAll(io.LimitReader(response.Body, 16*1024*1024+1))
	if err != nil {
		return err
	}
	if len(responseData) > 16*1024*1024 {
		return errors.New("Kubernetes response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := string(responseData)
		if len(message) > 2048 {
			message = message[:2048]
		}
		return &StatusError{Code: response.StatusCode, Message: message}
	}
	if out != nil && len(responseData) > 0 {
		return json.Unmarshal(responseData, out)
	}
	return nil
}

func (c *Client) Upsert(ctx context.Context, collection, name string, object map[string]any) error {
	var existing map[string]any
	err := c.Request(ctx, http.MethodGet, collection+"/"+url.PathEscape(name), nil, &existing)
	if IsNotFound(err) {
		return c.Request(ctx, http.MethodPost, collection, object, nil)
	}
	if err != nil {
		return err
	}
	metadata, ok := existing["metadata"].(map[string]any)
	if !ok {
		return errors.New("existing object has no metadata")
	}
	newMetadata, ok := object["metadata"].(map[string]any)
	if !ok {
		return errors.New("new object has no metadata")
	}
	newMetadata["resourceVersion"] = metadata["resourceVersion"]
	return c.Request(ctx, http.MethodPut, collection+"/"+url.PathEscape(name), object, nil)
}

type ConfigMap struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Data map[string]string `json:"data"`
}

func (c *Client) ConfigMaps(ctx context.Context, namespace, selector string) ([]ConfigMap, error) {
	var list struct {
		Items []ConfigMap `json:"items"`
	}
	err := c.Request(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/configmaps?labelSelector="+url.QueryEscape(selector), nil, &list)
	return list.Items, err
}

func (c *Client) PublishProbe(ctx context.Context, namespace, name string, report any) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	object := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": name, "namespace": namespace, "labels": map[string]string{"sentrycheck.io/type": "node-probe"}}, "data": map[string]string{"report.json": string(data)}}
	return c.Upsert(ctx, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/configmaps", name, object)
}
