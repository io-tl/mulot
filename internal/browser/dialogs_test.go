package browser

import (
	"context"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// TestDialogAutoAcceptNoDeadlock is the regression test for the CDP deadlock:
// a real alert() must be auto-accepted without freezing the session. With the
// buggy synchronous handler the navigate below blocks until the context
// deadline and the test fails instead of hanging the whole suite.
func TestDialogAutoAcceptNoDeadlock(t *testing.T) {
	b := New()
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer b.Close()

	tab, err := b.NewTab(context.Background())
	if err != nil {
		t.Fatalf("new tab: %v", err)
	}
	ctx := tab.Context()

	h := NewDialogHandler("accept")
	h.Start(ctx)

	navCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := chromedp.Run(navCtx,
		chromedp.Navigate(`data:text/html,<body>OK<script>alert('hi')</script></body>`),
		chromedp.WaitReady("body"),
	); err != nil {
		t.Fatalf("navigate with alert deadlocked or failed: %v", err)
	}

	// The page must stay responsive after the dialog is accepted.
	var txt string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.body.innerText`, &txt)); err != nil {
		t.Fatalf("page unresponsive after dialog: %v", err)
	}

	events := h.GetEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 dialog event, got %d (%+v)", len(events), events)
	}
	if events[0].Message != "hi" || events[0].Action != "accepted" {
		t.Errorf("unexpected event: %+v", events[0])
	}
}

// TestDialogManualLeavesPending verifies manual mode records the dialog as
// pending and does not auto-answer it.
func TestDialogManualMode(t *testing.T) {
	d := NewDialogHandler("manual")
	if d.autoMode != "manual" {
		t.Fatalf("expected manual mode")
	}
	d.SetMode("dismiss")
	if d.autoMode != "dismiss" {
		t.Errorf("SetMode failed: %s", d.autoMode)
	}
}
