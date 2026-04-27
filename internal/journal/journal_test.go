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
