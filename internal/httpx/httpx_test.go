package httpx

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
