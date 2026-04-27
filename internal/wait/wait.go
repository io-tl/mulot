// Package wait provides deterministic waiting primitives so an agent can
// synchronize on page state after a non-blocking action (click, type, JS eval).
// Without it, an agent has to poll browser_snapshot in a loop and races against
// AJAX / SPA navigation.
package wait

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// Condition describes what to wait for. Several fields may be set at once; all
// requested conditions must be satisfied before the timeout, evaluated in this
// order: network idle, selector state, text, url. Leave a field empty to skip it.
type Condition struct {
	Selector    string // CSS selector to wait on
	State       string // "visible" (default), "hidden", "present", "absent"
	Text        string // substring that must appear in the page's visible text
	URLContains string // substring the current URL must contain
	NetworkIdle bool   // wait until there are no in-flight network requests
	TimeoutMs   int    // overall budget; default 10000
}

// InFlightFunc reports how many network requests are currently in-flight.
type InFlightFunc func() int

const (
	defaultTimeout = 10 * time.Second
	pollInterval   = 100 * time.Millisecond
	idleDebounce   = 500 * time.Millisecond
)

// ErrTimeout is returned (wrapped) when a condition is not met before the deadline.
var ErrTimeout = errors.New("timeout")

// For blocks until every requested condition in c is met, or the timeout fires.
// It returns a summary describing which conditions were satisfied and the final
// URL/title, so the caller doesn't need a follow-up round-trip.
func For(ctx context.Context, c Condition, inFlight InFlightFunc) (map[string]any, error) {
	timeout := time.Duration(c.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	satisfied := []string{}

	if c.NetworkIdle {
		if err := waitNetworkIdle(tctx, inFlight); err != nil {
			return nil, describe("network_idle", err)
		}
		satisfied = append(satisfied, "network_idle")
	}

	if c.Selector != "" {
		state := c.State
		if state == "" {
			state = "visible"
		}
		if err := waitSelector(tctx, c.Selector, state); err != nil {
			return nil, describe(fmt.Sprintf("selector %q to be %s", c.Selector, state), err)
		}
		satisfied = append(satisfied, fmt.Sprintf("selector:%s", state))
	}

	if c.Text != "" {
		if err := waitText(tctx, c.Text); err != nil {
			return nil, describe(fmt.Sprintf("text %q", c.Text), err)
		}
		satisfied = append(satisfied, "text")
	}

	if c.URLContains != "" {
		if err := waitURLContains(tctx, c.URLContains); err != nil {
			return nil, describe(fmt.Sprintf("url to contain %q", c.URLContains), err)
		}
		satisfied = append(satisfied, "url")
	}

	if len(satisfied) == 0 {
		// No explicit condition: settle the page (document ready + network idle).
		_ = chromedp.Run(tctx, chromedp.WaitReady("body"))
		if inFlight != nil {
			_ = waitNetworkIdle(tctx, inFlight)
		}
		satisfied = append(satisfied, "page_settled")
	}

	var url, title string
	chromedp.Run(ctx, chromedp.Location(&url))
	chromedp.Run(ctx, chromedp.Title(&title))

	return map[string]any{
		"satisfied": satisfied,
		"elapsedMs": time.Since(start).Milliseconds(),
		"url":       url,
		"title":     title,
	}, nil
}

func waitSelector(ctx context.Context, sel, state string) error {
	var action chromedp.Action
	switch state {
	case "visible":
		action = chromedp.WaitVisible(sel, chromedp.ByQuery)
	case "hidden":
		action = chromedp.WaitNotVisible(sel, chromedp.ByQuery)
	case "present":
		action = chromedp.WaitReady(sel, chromedp.ByQuery)
	case "absent":
		action = chromedp.WaitNotPresent(sel, chromedp.ByQuery)
	default:
		return fmt.Errorf("unknown state %q (use visible, hidden, present, or absent)", state)
	}
	return chromedp.Run(ctx, action)
}

func waitText(ctx context.Context, text string) error {
	return poll(ctx, func() (bool, error) {
		var found bool
		expr := fmt.Sprintf(`(document.body ? document.body.innerText : "").includes(%s)`, jsString(text))
		if err := chromedp.Run(ctx, chromedp.Evaluate(expr, &found)); err != nil {
			return false, nil // transient (e.g. mid-navigation); keep polling
		}
		return found, nil
	})
}

func waitURLContains(ctx context.Context, sub string) error {
	return poll(ctx, func() (bool, error) {
		var url string
		if err := chromedp.Run(ctx, chromedp.Location(&url)); err != nil {
			return false, nil
		}
		return strings.Contains(url, sub), nil
	})
}

// waitNetworkIdle waits until inFlight() stays at zero for idleDebounce.
func waitNetworkIdle(ctx context.Context, inFlight InFlightFunc) error {
	if inFlight == nil {
		return nil
	}
	var idleSince time.Time
	return poll(ctx, func() (bool, error) {
		if inFlight() == 0 {
			if idleSince.IsZero() {
				idleSince = time.Now()
			}
			return time.Since(idleSince) >= idleDebounce, nil
		}
		idleSince = time.Time{}
		return false, nil
	})
}

// poll runs check every pollInterval until it returns true or ctx is done.
func poll(ctx context.Context, check func() (bool, error)) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		ok, err := check()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// describe turns a context deadline into an agent-friendly timeout message.
func describe(what string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: gave up waiting for %s", ErrTimeout, what)
	}
	return fmt.Errorf("waiting for %s: %w", what, err)
}

func jsString(s string) string {
	// JSON encoding produces a valid, safely-escaped JS string literal.
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
