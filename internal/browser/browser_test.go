package browser

import (
	"context"
	"testing"

	"github.com/chromedp/chromedp"
)

func TestNewBrowser(t *testing.T) {
	b := New()
	if !b.opts.Headless {
		t.Error("expected headless=true by default")
	}
	if b.opts.WindowSize != [2]int{1280, 720} {
		t.Errorf("expected default window size 1280x720, got %v", b.opts.WindowSize)
	}
}

func TestNewBrowserWithOptions(t *testing.T) {
	b := New(
		WithHeadless(false),
		WithProxy("http://proxy:8080"),
		WithWindowSize(1920, 1080),
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
