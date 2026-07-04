package journal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func tab(t *testing.T) (context.Context, func()) {
	t.Helper()
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
		)...)
	ctx, ctxCancel := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(ctx); err != nil {
		ctxCancel()
		allocCancel()
		t.Fatalf("chromium unavailable: %v", err)
	}
	return ctx, func() { ctxCancel(); allocCancel() }
}

func TestJournalCapturesAndReplays(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"secret":"j-token-42"}`))
	}))
	defer srv.Close()

	jr, err := Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer jr.Close()

	ctx, cancel := tab(t)
	defer cancel()
	jr.Start(ctx)

	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/api/users")); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	// The worker writes asynchronously — poll for the flow.
	var flows []FlowRow
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		flows, _ = jr.Query(Filter{URLContains: "/api/users"})
		if len(flows) > 0 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if len(flows) == 0 {
		t.Fatal("expected the /api/users request to be journaled")
	}
	f := flows[0]
	if f.Status != 200 || f.Method != "GET" {
		t.Errorf("unexpected flow: %+v", f)
	}

	// The JSON body must be stored and queryable.
	body, _, err := jr.Body(f.ID, "response")
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if !strings.Contains(string(body), "j-token-42") {
		t.Errorf("response body not captured, got %q", string(body))
	}

	// body_contains filter should find it too.
	hits, _ := jr.Query(Filter{BodyContains: "j-token-42"})
	if len(hits) == 0 {
		t.Error("body_contains filter did not match the stored body")
	}

	// ForReplay reconstructs the request.
	rd, err := jr.ForReplay(f.ID)
	if err != nil {
		t.Fatalf("ForReplay: %v", err)
	}
	if rd.Method != "GET" || !strings.Contains(rd.URL, "/api/users") {
		t.Errorf("unexpected replay data: %+v", rd)
	}

	// Clear empties the journal.
	if err := jr.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if remaining, _ := jr.Query(Filter{}); len(remaining) != 0 {
		t.Errorf("expected empty journal after Clear, got %d", len(remaining))
	}
}

// TestJournalCapturesRedirectHeaders is the regression test for the natas28
// gap: a 3xx hop (delivered by CDP via RedirectResponse, not responseReceived)
// must be recorded with its Location/custom headers, readable via Flow().
func TestJournalCapturesRedirectHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Secret-Blob", "blob123")
		http.Redirect(w, r, "/dest", http.StatusFound)
	})
	mux.HandleFunc("/dest", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("done"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	jr, err := Open(filepath.Join(t.TempDir(), "redir.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer jr.Close()

	ctx, cancel := tab(t)
	defer cancel()
	jr.Start(ctx)

	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/redir")); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	var redir []FlowRow
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		all, _ := jr.Query(Filter{URLContains: "/redir"})
		for _, f := range all {
			if f.Status == 302 {
				redir = append(redir, f)
			}
		}
		if len(redir) > 0 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if len(redir) == 0 {
		t.Fatal("the 302 redirect hop was not journaled")
	}

	d, err := jr.Flow(redir[0].ID)
	if err != nil || d == nil {
		t.Fatalf("Flow: %v", err)
	}
	if loc := headerCI(d.RespHeaders, "location"); !strings.Contains(loc, "/dest") {
		t.Errorf("Location header not captured, got %q", loc)
	}
	if headerCI(d.RespHeaders, "x-secret-blob") != "blob123" {
		t.Errorf("custom response header not captured: %v", d.RespHeaders)
	}
}

func headerCI(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func TestFindings(t *testing.T) {
	jr, err := Open(filepath.Join(t.TempDir(), "findings.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer jr.Close()

	if got, err := jr.Findings(); err != nil || len(got) != 0 {
		t.Fatalf("empty Findings: got %v err %v", got, err)
	}

	id1, err := jr.AddFinding("CTF{first}")
	if err != nil {
		t.Fatalf("AddFinding: %v", err)
	}
	id2, err := jr.AddFinding("second note")
	if err != nil {
		t.Fatalf("AddFinding: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected distinct ids, got %d and %d", id1, id2)
	}

	got, err := jr.Findings()
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d", len(got))
	}
	if got[0].Content != "CTF{first}" || got[1].Content != "second note" {
		t.Errorf("unexpected order/content: %+v", got)
	}
	if got[0].CreatedAt == 0 {
		t.Error("createdAt not set")
	}
}
