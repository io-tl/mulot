package httpx

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/io-tl/mulot/internal/envcfg"
)

func TestSendUserAgentFromEnv(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-UA", r.Header.Get("User-Agent"))
	}))
	defer srv.Close()

	t.Setenv(envcfg.UserAgentVar, "mulot-test-agent/1.0")

	resp, err := Send(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := resp.Headers["X-Seen-Ua"]; got != "mulot-test-agent/1.0" {
		t.Errorf("User-Agent = %q, want env override", got)
	}

	// An explicit header still wins over the env default.
	resp2, err := Send(context.Background(), Request{
		URL:     srv.URL,
		Headers: map[string]string{"User-Agent": "explicit-agent/2.0"},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := resp2.Headers["X-Seen-Ua"]; got != "explicit-agent/2.0" {
		t.Errorf("User-Agent = %q, want explicit header to win", got)
	}
}

func TestSendRoutesThroughEnvProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Via-Proxy", "1")
		w.Write([]byte("proxied"))
	}))
	defer proxy.Close()

	t.Setenv(envcfg.ProxyVar, proxy.URL)

	// This target would fail to resolve if dialed directly — it's only
	// reachable through the proxy above, which answers any request
	// regardless of destination.
	resp, err := Send(context.Background(), Request{URL: "http://mulot-test-target.invalid/"})
	if err != nil {
		t.Fatalf("Send should have gone through the proxy: %v", err)
	}
	if resp.Headers["X-Via-Proxy"] != "1" || resp.Body != "proxied" {
		t.Errorf("response = %+v, want to see it routed via the proxy", resp)
	}
}

func TestSendNoProxyByDefault(t *testing.T) {
	t.Setenv(envcfg.ProxyVar, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("direct"))
	}))
	defer srv.Close()

	resp, err := Send(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.Body != "direct" {
		t.Errorf("body = %q, want direct (no proxy)", resp.Body)
	}
}

func TestSendIgnoresBadCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	resp, err := Send(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Send should not fail on a self-signed cert: %v", err)
	}
	if resp.Status != 200 || resp.Body != "ok" {
		t.Errorf("status/body = %d/%q, want 200/ok", resp.Status, resp.Body)
	}
}

func TestSendPassesMethodHeaderCookieBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Method", r.Method)
		w.Header().Set("X-Seen-Origin", r.Header.Get("Origin"))
		if c, err := r.Cookie("session"); err == nil {
			w.Header().Set("X-Seen-Cookie", c.Value)
		}
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("got:" + string(body)))
	}))
	defer srv.Close()

	resp, err := Send(context.Background(), Request{
		Method:  "POST",
		URL:     srv.URL,
		Headers: map[string]string{"Origin": "https://evil.com"},
		Body:    "x=1",
		Cookies: []*http.Cookie{{Name: "session", Value: "abc"}},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.Status != 201 {
		t.Errorf("status = %d, want 201", resp.Status)
	}
	if resp.Headers["X-Seen-Method"] != "POST" {
		t.Errorf("method not passed: %q", resp.Headers["X-Seen-Method"])
	}
	if resp.Headers["X-Seen-Origin"] != "https://evil.com" {
		t.Errorf("Origin header not passed: %q", resp.Headers["X-Seen-Origin"])
	}
	if resp.Headers["X-Seen-Cookie"] != "abc" {
		t.Errorf("cookie not passed: %q", resp.Headers["X-Seen-Cookie"])
	}
	if !strings.Contains(resp.Body, "got:x=1") {
		t.Errorf("body not passed: %q", resp.Body)
	}
}

func TestSendRedirectControl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/r", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dest", http.StatusFound)
	})
	mux.HandleFunc("/dest", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("DEST"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Default: do NOT follow — see the 302 and its Location.
	resp, err := Send(context.Background(), Request{URL: srv.URL + "/r"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.Status != 302 {
		t.Errorf("expected 302, got %d", resp.Status)
	}
	if !strings.Contains(resp.Headers["Location"], "/dest") {
		t.Errorf("expected Location to /dest, got %q", resp.Headers["Location"])
	}

	// Follow: end up at /dest.
	resp2, err := Send(context.Background(), Request{URL: srv.URL + "/r", FollowRedirects: true})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp2.Status != 200 || resp2.Body != "DEST" {
		t.Errorf("expected 200/DEST, got %d/%q", resp2.Status, resp2.Body)
	}
	if !resp2.Redirected {
		t.Error("expected Redirected=true")
	}
}
