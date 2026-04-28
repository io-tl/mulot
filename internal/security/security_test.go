package security

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/io-tl/mulot/internal/journal"
)

func TestAuditSecurityHeaders(t *testing.T) {
	resps := []journal.ResponseView{
		{URL: "http://x/a", Status: 200, RespHeaders: map[string]string{
			// mixed casing — lookup must be case-insensitive
			"Content-Security-Policy": "default-src 'self'",
			"X-Frame-Options":         "DENY",
		}},
		{URL: "http://x/b", Status: 200, RespHeaders: map[string]string{}},
		// duplicate URL, later response wins (now carries HSTS)
		{URL: "http://x/a", Status: 200, RespHeaders: map[string]string{
			"strict-transport-security": "max-age=63072000",
		}},
	}
	audits := AuditSecurityHeaders(resps)
	if len(audits) != 2 {
		t.Fatalf("expected 2 deduped audits, got %d: %+v", len(audits), audits)
	}
	byURL := map[string]HeaderAudit{}
	for _, a := range audits {
		byURL[a.URL] = a
	}
	if _, ok := byURL["http://x/a"].Present["strict-transport-security"]; !ok {
		t.Errorf("/a should reflect the latest response (HSTS present): %+v", byURL["http://x/a"])
	}
	if len(byURL["http://x/b"].Missing) != 5 {
		t.Errorf("/b should be missing all 5 required headers, got %v", byURL["http://x/b"].Missing)
	}
}

func TestScanForSecretsInNetworkFiltersByMime(t *testing.T) {
	resps := []journal.ResponseView{
		{URL: "http://x/app.js", MimeType: "application/javascript", Body: `var token = "supersecrettoken123";`},
		{URL: "http://x/page", MimeType: "text/html", Body: `password=shouldNotBeScanned`},
		{URL: "http://x/empty", MimeType: "application/json", Body: ``},
	}
	f := ScanForSecretsInNetwork(resps)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (js body only), got %d: %+v", len(f), f)
	}
	if f[0].URL != "http://x/app.js" {
		t.Errorf("unexpected finding URL: %s", f[0].URL)
	}
}

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
