package kube

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestPatchUsesMergePatchAndChecksHTTPStatus(t *testing.T) {
	c := Client{BaseURL: "https://kubernetes.invalid", HTTP: &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Content-Type") != "application/merge-patch+json" {
			t.Fatal(r.Header)
		}
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"message":"forbidden"}`)), Header: make(http.Header)}, nil
	})}}
	if err := c.Request(context.Background(), http.MethodPatch, "/api/v1/nodes/node1", map[string]any{"metadata": map[string]any{}}, nil); err == nil {
		t.Fatal("forbidden write reported as successful")
	}
}
