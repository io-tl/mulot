package fuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/io-tl/mulot/internal/httpx"
)

// echoServer reflects the id query param and 200s for "good", 500s otherwise,
// so a test can assert both the substitution and the match logic.
func echoServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "good" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("welcome " + id))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error for " + id))
	}))
}

func TestRunSubstitutesMarkerInURL(t *testing.T) {
	srv := echoServer()
	defer srv.Close()

	out, err := Run(context.Background(), Params{
		Base:     httpx.Request{URL: srv.URL + "/?id=FUZZ"},
		Payloads: []string{"good", "bad"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Count != 2 || len(out.Results) != 2 {
		t.Fatalf("expected 2 results, got count=%d len=%d", out.Count, len(out.Results))
	}
	if out.Results[0].Payload != "good" || out.Results[0].Status != 200 {
		t.Errorf("row0 = %+v, want payload=good status=200", out.Results[0])
	}
	if out.Results[1].Status != 500 {
		t.Errorf("row1 status = %d, want 500", out.Results[1].Status)
	}
	// Without match criteria, Matched stays false.
	if out.Results[0].Matched {
		t.Error("Matched should be unset when no criterion is given")
	}
}

func TestRunMatchStatusAndRegex(t *testing.T) {
	srv := echoServer()
	defer srv.Close()

	out, err := Run(context.Background(), Params{
		Base:        httpx.Request{URL: srv.URL + "/?id=FUZZ"},
		Payloads:    []string{"good", "bad"},
		MatchStatus: 200,
		MatchRegex:  "welcome",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Results[0].Matched {
		t.Error("row0 (good/200/welcome) should match")
	}
	if out.Results[1].Matched {
		t.Error("row1 (bad/500) should not match")
	}
}

func TestRunCustomMarkerInBody(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		seen = string(b)
	}))
	defer srv.Close()

	_, err := Run(context.Background(), Params{
		Base:     httpx.Request{Method: "POST", URL: srv.URL, Body: "user=admin&pass=§P§"},
		Marker:   "§P§",
		Payloads: []string{"secret"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(seen, "pass=secret") {
		t.Errorf("body marker not substituted, server saw %q", seen)
	}
}

func TestRunRejectsEmptyAndOversizedPayloads(t *testing.T) {
	if _, err := Run(context.Background(), Params{Base: httpx.Request{URL: "http://x"}}); err == nil {
		t.Error("expected error for empty payloads")
	}

	big := make([]string, MaxPayloads+1)
	for i := range big {
		big[i] = "x"
	}
	if _, err := Run(context.Background(), Params{Base: httpx.Request{URL: "http://x"}, Payloads: big}); err == nil {
		t.Errorf("expected error when payloads exceed cap of %d", MaxPayloads)
	}
}

func TestRunInvalidRegex(t *testing.T) {
	if _, err := Run(context.Background(), Params{
		Base:       httpx.Request{URL: "http://x"},
		Payloads:   []string{"a"},
		MatchRegex: "(",
	}); err == nil {
		t.Error("expected error for invalid match_regex")
	}
}
