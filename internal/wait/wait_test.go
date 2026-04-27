package wait

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/chromedp/chromedp"
)

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

func load(t *testing.T, ctx context.Context, html string) {
	t.Helper()
	if err := chromedp.Run(ctx,
		chromedp.Navigate(dataURL(html)),
		chromedp.WaitReady("body"),
	); err != nil {
		t.Fatalf("navigate: %v", err)
	}
}

func TestWaitForSelectorVisible(t *testing.T) {
	ctx, cancel := newTab(t)
	defer cancel()
	load(t, ctx, `<body><div id="late" style="display:none">hi</div>
		<script>setTimeout(function(){document.getElementById('late').style.display='block'},300)</script></body>`)

	res, err := For(ctx, Condition{Selector: "#late", State: "visible", TimeoutMs: 3000}, nil)
	if err != nil {
		t.Fatalf("expected visible, got error: %v", err)
	}
	if got := res["satisfied"].([]string); len(got) == 0 || got[0] != "selector:visible" {
		t.Errorf("unexpected satisfied: %v", got)
	}
}

func TestWaitForText(t *testing.T) {
	ctx, cancel := newTab(t)
	defer cancel()
	load(t, ctx, `<body><p id="p">…</p>
		<script>setTimeout(function(){document.getElementById('p').textContent='LOADED'},200)</script></body>`)

	if _, err := For(ctx, Condition{Text: "LOADED", TimeoutMs: 3000}, nil); err != nil {
		t.Fatalf("expected text to appear, got error: %v", err)
	}
}

func TestWaitTimeoutReturnsErrTimeout(t *testing.T) {
	ctx, cancel := newTab(t)
	defer cancel()
	load(t, ctx, `<body><p>nothing here</p></body>`)

	_, err := For(ctx, Condition{Selector: "#never", State: "visible", TimeoutMs: 500}, nil)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrTimeout, got %v", err)
	}
}

func TestWaitNetworkIdleDebounce(t *testing.T) {
	ctx, cancel := newTab(t)
	defer cancel()
	load(t, ctx, `<body>idle test</body>`)

	// Simulate two in-flight polls, then steady idle.
	n := 0
	inFlight := func() int {
		n++
		if n <= 2 {
			return 1
		}
		return 0
	}

	res, err := For(ctx, Condition{NetworkIdle: true, TimeoutMs: 3000}, inFlight)
	if err != nil {
		t.Fatalf("expected network idle, got error: %v", err)
	}
	if got := res["satisfied"].([]string); len(got) == 0 || got[0] != "network_idle" {
		t.Errorf("unexpected satisfied: %v", got)
	}
}

func TestWaitNoConditionSettles(t *testing.T) {
	ctx, cancel := newTab(t)
	defer cancel()
	load(t, ctx, `<body>settled</body>`)

	res, err := For(ctx, Condition{TimeoutMs: 2000}, func() int { return 0 })
	if err != nil {
		t.Fatalf("expected settle, got error: %v", err)
	}
	if got := res["satisfied"].([]string); len(got) == 0 || got[0] != "page_settled" {
		t.Errorf("expected page_settled, got %v", got)
	}
}

func TestJSStringEscaping(t *testing.T) {
	cases := map[string]string{
		`hi`:         `"hi"`,
		`a"b`:        `"a\"b"`,
		"a\nb":       `"a\nb"`,
		`back\slash`: `"back\\slash"`,
	}
	for in, want := range cases {
		if got := jsString(in); got != want {
			t.Errorf("jsString(%q) = %s, want %s", in, got, want)
		}
	}
}
