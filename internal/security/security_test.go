package security

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chromedp/chromedp"
)

// reflectServer echoes the ?q= parameter back into the page, either raw
// (reflected XSS) or HTML-escaped (safe).
func reflectServer(escape bool) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if escape {
			q = html.EscapeString(q)
		}
		fmt.Fprintf(w, `<!doctype html><html><body>
			<form method="get" action="/">
				<input type="text" name="q">
				<input type="submit" value="Go">
			</form>
			<div id="out">%s</div></body></html>`, q)
	})
	return httptest.NewServer(mux)
}

func xssTab(t *testing.T) (context.Context, func()) {
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

var onePayload = []string{`<img src=x onerror="window['MARKER']=1">`}

func TestXSSDetectsReflected(t *testing.T) {
	srv := reflectServer(false)
	defer srv.Close()
	ctx, cancel := xssTab(t)
	defer cancel()

	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/"), chromedp.WaitReady("body")); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	res, err := TestXSS(ctx, `input[name="q"]`, `input[type="submit"]`, onePayload)
	if err != nil {
		t.Fatalf("TestXSS: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected reflected XSS to be detected, got %+v", res)
	}
	if len(res.Findings) == 0 || !res.Findings[0].Executed {
		t.Errorf("expected an executed finding, got %+v", res.Findings)
	}
}

func TestXSSSafeWhenEscaped(t *testing.T) {
	srv := reflectServer(true)
	defer srv.Close()
	ctx, cancel := xssTab(t)
	defer cancel()

	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/"), chromedp.WaitReady("body")); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	res, err := TestXSS(ctx, `input[name="q"]`, `input[type="submit"]`, onePayload)
	if err != nil {
		t.Fatalf("TestXSS: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("escaped output must not be flagged vulnerable, got %+v", res.Findings)
	}
}
