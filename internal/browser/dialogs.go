package browser

import (
	"context"
	"sync"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

type DialogEvent struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	URL     string `json:"url,omitempty"`
	Handled bool   `json:"handled"`
	Action  string `json:"action"`
}

type DialogHandler struct {
	mu       sync.Mutex
	events   []DialogEvent
	autoMode string // "accept", "dismiss", "manual"
	active   bool
}

func NewDialogHandler(autoMode string) *DialogHandler {
	if autoMode == "" {
		autoMode = "accept"
	}
	return &DialogHandler{
		autoMode: autoMode,
		active:   true,
	}
}

func (d *DialogHandler) Start(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(ev any) {
		e, ok := ev.(*page.EventJavascriptDialogOpening)
		if !ok {
			return
		}

		d.mu.Lock()
		if !d.active {
			d.mu.Unlock()
			return
		}
		mode := d.autoMode
		event := DialogEvent{
			Type:    string(e.Type),
			Message: e.Message,
			URL:     e.URL,
		}
		switch mode {
		case "accept":
			event.Handled = true
			event.Action = "accepted"
		case "dismiss":
			event.Handled = true
			event.Action = "dismissed"
		default:
			event.Handled = false
			event.Action = "pending"
		}
		d.events = append(d.events, event)
		d.mu.Unlock()

		// A JS dialog pauses the page until it is answered. The answering CDP
		// command MUST run outside this ListenTarget callback: calling
		// chromedp.Run synchronously here deadlocks the CDP event loop — the
		// callback blocks waiting for a response that cannot be processed until
		// the callback returns. So dispatch it on its own goroutine. In "manual"
		// mode we leave the dialog open for browser_handle_dialog.
		if mode == "accept" || mode == "dismiss" {
			accept := mode == "accept"
			go func() { _ = chromedp.Run(ctx, page.HandleJavaScriptDialog(accept)) }()
		}
	})
}

func (d *DialogHandler) GetEvents() []DialogEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]DialogEvent, len(d.events))
	copy(result, d.events)
	return result
}

func (d *DialogHandler) SetMode(mode string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.autoMode = mode
}

func (d *DialogHandler) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = nil
}

func (d *DialogHandler) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.active = false
}

func HandleDialog(ctx context.Context, accept bool, promptText string) error {
	if promptText != "" {
		return chromedp.Run(ctx,
			page.HandleJavaScriptDialog(accept).WithPromptText(promptText),
		)
	}
	return chromedp.Run(ctx, page.HandleJavaScriptDialog(accept))
}
