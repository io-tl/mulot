package browser

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

type RecoveryConfig struct {
	MaxRetries     int
	RetryDelay     time.Duration
	NavigateTimout time.Duration
}

func DefaultRecoveryConfig() RecoveryConfig {
	return RecoveryConfig{
		MaxRetries:     3,
		RetryDelay:     2 * time.Second,
		NavigateTimout: 30 * time.Second,
	}
}

func (b *Browser) RunWithRecovery(ctx context.Context, cfg RecoveryConfig, url string, actions ...chromedp.Action) error {
	var lastErr error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(cfg.RetryDelay)
			if err := b.recover(ctx, url); err != nil {
				lastErr = fmt.Errorf("recovery attempt %d failed: %w", attempt, err)
				continue
			}
		}

		timeoutCtx, cancel := context.WithTimeout(ctx, cfg.NavigateTimout)
		err := chromedp.Run(timeoutCtx, actions...)
		cancel()

		if err == nil {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("all %d attempts failed, last error: %w", cfg.MaxRetries+1, lastErr)
}

func (b *Browser) recover(ctx context.Context, url string) error {
	b.mu.Lock()
	oldTab := b.tab()
	b.mu.Unlock()

	if oldTab != nil {
		oldTab.Close()
	}

	tab, err := b.NewTab(ctx)
	if err != nil {
		return fmt.Errorf("create recovery tab: %w", err)
	}

	b.mu.Lock()
	b.setCurrentTab(tab)
	b.mu.Unlock()

	if url != "" {
		timeoutCtx, cancel := context.WithTimeout(tab.ctx, 10*time.Second)
		defer cancel()
		if err := chromedp.Run(timeoutCtx,
			chromedp.Navigate(url),
			chromedp.WaitReady("body"),
		); err != nil {
			return fmt.Errorf("navigate after recovery: %w", err)
		}
	}
	return nil
}

func (b *Browser) tab() *Tab {
	if len(b.tabs) == 0 {
		return nil
	}
	return b.tabs[len(b.tabs)-1]
}

func (b *Browser) setCurrentTab(t *Tab) {
	b.tabs = append(b.tabs, t)
}

func (b *Browser) HealthCheck(ctx context.Context) error {
	if b.allocCtx == nil {
		return fmt.Errorf("browser not started")
	}
	tab := b.tab()
	if tab == nil {
		return fmt.Errorf("no active tab")
	}

	checkCtx, cancel := context.WithTimeout(tab.ctx, 5*time.Second)
	defer cancel()

	var result bool
	if err := chromedp.Run(checkCtx, chromedp.Evaluate("true", &result)); err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	if !result {
		return fmt.Errorf("unexpected health check result")
	}
	return nil
}
