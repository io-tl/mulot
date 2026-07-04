package mcp

import (
	"context"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/io-tl/mulot/assets"
	"github.com/io-tl/mulot/internal/js"
)

// browserTab spins a real headless chromium tab; skips if chromium is missing.
func browserTab(t *testing.T) (context.Context, func()) {
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

// TestInjectCryptoRuntime runs the exact code browser_inject(helper="crypto")
// evaluates, then calls the injected functions in-page — this catches any
// chromedp serialization issue with the multi-statement/trailing-value script.
func TestInjectCryptoRuntime(t *testing.T) {
	ctx, done := browserTab(t)
	defer done()

	src, err := assets.JS("crypto")
	if err != nil {
		t.Fatal(err)
	}
	res, err := js.Evaluate(ctx, src+"\n\"ok\"")
	if err != nil {
		t.Fatalf("injecting crypto.js failed: %v", err)
	}
	if res != "ok" {
		t.Fatalf("inject completion value = %v, want \"ok\"", res)
	}

	md5, err := js.Evaluate(ctx, `window.mulotCrypto.md5("abc")`)
	if err != nil {
		t.Fatalf("mulotCrypto.md5 failed: %v", err)
	}
	if md5 != "900150983cd24fb0d6963f7d28e17f72" {
		t.Errorf("md5(abc) in-page = %v", md5)
	}
}

// TestInjectWordlistRuntime runs the exact code browser_inject(helper="wordlist")
// evaluates, then checks mulotWordlist returns a real JS array in-page.
func TestInjectWordlistRuntime(t *testing.T) {
	ctx, done := browserTab(t)
	defer done()

	code, err := wordlistInjectJS()
	if err != nil {
		t.Fatal(err)
	}
	if res, err := js.Evaluate(ctx, code); err != nil || res != "ok" {
		t.Fatalf("injecting wordlist failed: res=%v err=%v", res, err)
	}

	n, err := js.Evaluate(ctx, `window.mulotWordlist("pages").length`)
	if err != nil {
		t.Fatalf("mulotWordlist length failed: %v", err)
	}
	if f, ok := n.(float64); !ok || f <= 0 {
		t.Fatalf("mulotWordlist('pages').length = %v (want > 0)", n)
	}

	first, err := js.Evaluate(ctx, `window.mulotWordlist("pages")[0]`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first.(string); !ok {
		t.Fatalf("wordlist entry is not a string: %T %v", first, first)
	}

	// Unknown tag returns an empty array (no throw).
	empty, err := js.Evaluate(ctx, `window.mulotWordlist("nope").length`)
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := empty.(float64); !ok || f != 0 {
		t.Errorf("unknown tag length = %v (want 0)", empty)
	}
}
