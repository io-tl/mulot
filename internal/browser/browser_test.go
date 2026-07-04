package browser

import (
	"context"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/io-tl/mulot/internal/envcfg"
)

// clearBrowserEnv isolates a test from any MULOT_* var set in the ambient
// environment, so defaults are deterministic regardless of who runs it.
func clearBrowserEnv(t *testing.T) {
	t.Helper()
	t.Setenv(envcfg.UserAgentVar, "")
	t.Setenv(envcfg.HeadlessVar, "")
	t.Setenv(envcfg.ProxyVar, "")
}

func TestNewBrowser(t *testing.T) {
	clearBrowserEnv(t)
	b := New()
	if !b.opts.Headless {
		t.Error("expected headless=true by default")
	}
	if b.opts.WindowSize != [2]int{1280, 720} {
		t.Errorf("expected default window size 1280x720, got %v", b.opts.WindowSize)
	}
	if b.opts.UserAgent != "" {
		t.Errorf("expected empty UserAgent by default, got %q", b.opts.UserAgent)
	}
	if b.opts.ProxyURL != "" {
		t.Errorf("expected empty ProxyURL by default, got %q", b.opts.ProxyURL)
	}
}

func TestNewBrowserWithOptions(t *testing.T) {
	clearBrowserEnv(t)
	b := New(
		WithHeadless(false),
		WithProxy("http://proxy:8080"),
		WithWindowSize(1920, 1080),
		WithUserAgent("custom-agent/1.0"),
	)
	if b.opts.Headless {
		t.Error("expected headless=false")
	}
	if b.opts.ProxyURL != "http://proxy:8080" {
		t.Errorf("expected proxy, got %q", b.opts.ProxyURL)
	}
	if b.opts.WindowSize != [2]int{1920, 1080} {
		t.Errorf("expected 1920x1080, got %v", b.opts.WindowSize)
	}
	if b.opts.UserAgent != "custom-agent/1.0" {
		t.Errorf("expected custom-agent/1.0, got %q", b.opts.UserAgent)
	}
}

func TestNewBrowserUserAgentFromEnv(t *testing.T) {
	clearBrowserEnv(t)
	t.Setenv(envcfg.UserAgentVar, "env-agent/3.0")
	b := New()
	if b.opts.UserAgent != "env-agent/3.0" {
		t.Errorf("expected env-agent/3.0, got %q", b.opts.UserAgent)
	}

	// An explicit option still wins over the env default.
	b2 := New(WithUserAgent("explicit-agent/4.0"))
	if b2.opts.UserAgent != "explicit-agent/4.0" {
		t.Errorf("expected explicit option to win, got %q", b2.opts.UserAgent)
	}
}

func TestNewBrowserHeadlessFromEnv(t *testing.T) {
	clearBrowserEnv(t)
	t.Setenv(envcfg.HeadlessVar, "false")
	b := New()
	if b.opts.Headless {
		t.Error("expected headless=false from MULOT_HEADLESS=false")
	}

	// An explicit option still wins over the env default.
	b2 := New(WithHeadless(true))
	if !b2.opts.Headless {
		t.Error("expected explicit WithHeadless(true) to win over env")
	}
}

func TestNewBrowserProxyFromEnv(t *testing.T) {
	clearBrowserEnv(t)
	t.Setenv(envcfg.ProxyVar, "http://env-proxy:9090")
	b := New()
	if b.opts.ProxyURL != "http://env-proxy:9090" {
		t.Errorf("expected env proxy, got %q", b.opts.ProxyURL)
	}

	// An explicit option still wins over the env default.
	b2 := New(WithProxy("http://explicit-proxy:1234"))
	if b2.opts.ProxyURL != "http://explicit-proxy:1234" {
		t.Errorf("expected explicit proxy to win, got %q", b2.opts.ProxyURL)
	}
}

func TestBrowserStartAndClose(t *testing.T) {
	b := New()
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestBrowserSurvivesCanceledStartCtx(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	if err := b.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	tab, err := b.NewTab(context.Background())
	if err != nil {
		t.Fatalf("new tab failed: %v", err)
	}
	cancel()

	if err := tab.Run(chromedp.Navigate("about:blank")); err != nil {
		t.Fatalf("navigate after cancel should work but got: %v", err)
	}
	b.Close()
}
