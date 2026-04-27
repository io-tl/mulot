package navigation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chromedp/chromedp"
	"github.com/io-tl/mulot/internal/network"
)

type LinkCheckResult struct {
	URL        string `json:"url"`
	Text       string `json:"text"`
	Status     int64  `json:"status"`
	FinalURL   string `json:"finalUrl,omitempty"`
	Redirected bool   `json:"redirected"`
	Broken     bool   `json:"broken"`
	Skipped    bool   `json:"skipped,omitempty"`
	SkipReason string `json:"skipReason,omitempty"`
	Error      string `json:"error,omitempty"`
}

// stateChangingKeywords mark links that mutate server state. Following them in
// the shared cookie jar would (e.g.) log the session out or delete data, so
// they are reported but never fetched.
var stateChangingKeywords = []string{
	"logout", "signout", "sign-out", "logoff", "log-off",
	"/delete", "/destroy", "/remove", "/drop", "/reset",
	"action=delete", "action=logout", "do=logout", "/setup.php",
}

// skipReason returns a non-empty reason if a link must not be fetched: a
// same-page anchor, or a state-changing action.
func skipReason(rawURL, currentURL string) string {
	frag := strings.SplitN(rawURL, "#", 2)
	base := frag[0]
	if base == "" || base == currentURL {
		return "same-page anchor"
	}
	lower := strings.ToLower(rawURL)
	for _, kw := range stateChangingKeywords {
		if strings.Contains(lower, kw) {
			return "state-changing link (" + kw + ")"
		}
	}
	return ""
}

func CheckLinks(ctx context.Context) ([]LinkCheckResult, error) {
	var linksJSON string
	err := chromedp.Run(ctx,
		chromedp.Evaluate(`(function(){
			var links = document.querySelectorAll('a[href]');
			var result = [];
			links.forEach(function(a) {
				var href = a.href;
				if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('tel:')) {
					result.push({url: href, text: (a.textContent||'').trim().substring(0,100)});
				}
			});
			return JSON.stringify(result);
		})()`, &linksJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("extract links: %w", err)
	}

	type linkInfo struct {
		URL  string `json:"url"`
		Text string `json:"text"`
	}

	var links []linkInfo
	if err := parseJSON(linksJSON, &links); err != nil {
		return nil, err
	}

	var currentURL string
	chromedp.Run(ctx, chromedp.Location(&currentURL))

	var results []LinkCheckResult
	for _, link := range links {
		if reason := skipReason(link.URL, currentURL); reason != "" {
			results = append(results, LinkCheckResult{
				URL:        link.URL,
				Text:       link.Text,
				Skipped:    true,
				SkipReason: reason,
			})
			continue
		}
		result := checkSingleLink(ctx, link.URL, link.Text)
		results = append(results, result)
	}
	return results, nil
}

func checkSingleLink(ctx context.Context, url, text string) LinkCheckResult {
	result := LinkCheckResult{URL: url, Text: text}

	tabCtx, cancel := chromedp.NewContext(ctx)
	defer cancel()

	mon := network.NewMonitor()
	if err := mon.Start(tabCtx); err != nil {
		result.Broken = true
		result.Error = err.Error()
		return result
	}

	err := chromedp.Run(tabCtx,
		chromedp.Navigate(url),
		chromedp.WaitReady("body"),
	)
	if err != nil {
		result.Broken = true
		result.Error = err.Error()
		return result
	}

	var finalURL string
	chromedp.Run(tabCtx, chromedp.Location(&finalURL))
	result.FinalURL = finalURL
	result.Redirected = finalURL != url

	entries := mon.GetEntries()
	for _, e := range entries {
		if e.URL == url || e.URL == finalURL {
			result.Status = e.Status
			break
		}
	}

	result.Broken = result.Status >= 400 || result.Status == 0
	return result
}

func GetBrokenLinks(results []LinkCheckResult) []LinkCheckResult {
	var broken []LinkCheckResult
	for _, r := range results {
		if r.Broken && !r.Skipped {
			broken = append(broken, r)
		}
	}
	return broken
}

func parseJSON(data string, v any) error {
	return json.Unmarshal([]byte(data), v)
}
