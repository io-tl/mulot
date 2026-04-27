package dom

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/chromedp/chromedp"
)

const refTestHTML = `<!doctype html><html><head><title>Refs</title></head><body>
<h1>Welcome</h1>
<a href="/next">Continue</a>
<label for="email">Email</label><input id="email" type="text" placeholder="you@x.com">
<button aria-label="Submit form">Go</button>
<input type="hidden" name="csrf" value="xyz">
<div style="display:none"><a href="/hidden">Hidden link</a></div>
</body></html>`

func dataURL(html string) string {
	return "data:text/html;base64," + base64.StdEncoding.EncodeToString([]byte(html))
}

func newTab(t *testing.T) (context.Context, func()) {
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

func TestGetInteractiveAssignsRefs(t *testing.T) {
	ctx, cancel := newTab(t)
	defer cancel()

	if err := chromedp.Run(ctx,
		chromedp.Navigate(dataURL(refTestHTML)),
		chromedp.WaitReady("body"),
	); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	els, truncated, err := GetInteractive(ctx, 200)
	if err != nil {
		t.Fatalf("GetInteractive: %v", err)
	}
	if truncated {
		t.Error("unexpected truncation on small page")
	}

	byName := map[string]Interactive{}
	for _, e := range els {
		if e.Ref == "" {
			t.Errorf("element without ref: %+v", e)
		}
		byName[e.Name] = e
	}

	if _, ok := byName["Continue"]; !ok {
		t.Errorf("missing 'Continue' link; got %+v", els)
	}
	if e, ok := byName["Submit form"]; !ok || e.Role != "button" {
		t.Errorf("aria-label button missing/wrong: %+v", e)
	}
	if e, ok := byName["Email"]; !ok || e.Role != "textbox" {
		t.Errorf("labeled input missing/wrong: %+v", e)
	}

	for _, e := range els {
		if e.Name == "Hidden link" {
			t.Error("hidden (display:none) link should be excluded")
		}
		if e.Type == "hidden" {
			t.Error("type=hidden input should be excluded")
		}
	}

	// The ref must resolve back to the same element via its selector.
	cont := byName["Continue"]
	var href string
	var ok bool
	if err := chromedp.Run(ctx,
		chromedp.AttributeValue(RefSelector(cont.Ref), "href", &href, &ok),
	); err != nil {
		t.Fatalf("resolve ref selector: %v", err)
	}
	if !ok || href == "" {
		t.Errorf("ref %q did not resolve to the Continue link (href=%q ok=%v)", cont.Ref, href, ok)
	}
}

func TestClearFieldOnEmptyTextarea(t *testing.T) {
	ctx, cancel := newTab(t)
	defer cancel()
	if err := chromedp.Run(ctx,
		chromedp.Navigate(dataURL(`<body><textarea id="t"></textarea></body>`)),
		chromedp.WaitReady("body"),
	); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	// chromedp.Clear errors here ("no #text node"); ClearField must not.
	if err := ClearField(ctx, "#t"); err != nil {
		t.Errorf("ClearField on empty textarea failed: %v", err)
	}
	if err := ClearField(ctx, "#missing"); err == nil {
		t.Error("expected error for missing selector")
	}
}

func TestSelectOption(t *testing.T) {
	ctx, cancel := newTab(t)
	defer cancel()
	if err := chromedp.Run(ctx,
		chromedp.Navigate(dataURL(`<body><select id="s">
			<option value="l">Low</option>
			<option value="h">High</option></select></body>`)),
		chromedp.WaitReady("body"),
	); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	// By value.
	if err := SelectOption(ctx, "#s", "h"); err != nil {
		t.Fatalf("SelectOption by value: %v", err)
	}
	var val string
	chromedp.Run(ctx, chromedp.Evaluate(`document.querySelector('#s').value`, &val))
	if val != "h" {
		t.Errorf("expected value 'h', got %q", val)
	}

	// By visible label.
	if err := SelectOption(ctx, "#s", "Low"); err != nil {
		t.Fatalf("SelectOption by label: %v", err)
	}
	chromedp.Run(ctx, chromedp.Evaluate(`document.querySelector('#s').value`, &val))
	if val != "l" {
		t.Errorf("expected value 'l' after selecting by label, got %q", val)
	}

	if err := SelectOption(ctx, "#s", "nope"); err == nil {
		t.Error("expected error for unknown option")
	}
}
