package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"github.com/io-tl/mulot/internal/dom"
	"github.com/io-tl/mulot/internal/network"
	"github.com/io-tl/mulot/internal/wait"
)

type LoginResult struct {
	Success     bool            `json:"success"`
	Confidence  string          `json:"confidence,omitempty"` // high | low
	Reason      string          `json:"reason,omitempty"`
	FinalURL    string          `json:"finalUrl"`
	StatusCode  int64           `json:"statusCode,omitempty"`
	Cookies     []CookieInfo    `json:"cookies,omitempty"`
	ErrorMsg    string          `json:"error,omitempty"`
	FormFields  []dom.FormField `json:"formFields,omitempty"`
	RedirectURL string          `json:"redirectUrl,omitempty"`
}

type CookieInfo struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httpOnly"`
	SameSite string `json:"sameSite"`
}

type LoginParams struct {
	URL              string            `json:"url"`
	UsernameSelector string            `json:"usernameSelector"`
	PasswordSelector string            `json:"passwordSelector"`
	SubmitSelector   string            `json:"submitSelector"`
	Username         string            `json:"username"`
	Password         string            `json:"password"`
	ExtraFields      map[string]string `json:"extraFields,omitempty"`
	SuccessIndicator string            `json:"successIndicator,omitempty"`
	FailureIndicator string            `json:"failureIndicator,omitempty"`
	IsolateSession   bool              `json:"isolateSession,omitempty"`
}

func TestLogin(ctx context.Context, params LoginParams) (*LoginResult, error) {
	result := &LoginResult{}

	mon := network.NewMonitor()
	if err := mon.Start(ctx); err != nil {
		return nil, fmt.Errorf("start network monitor: %w", err)
	}
	defer mon.Stop()

	// Optional session isolation: start from a clean cookie jar so a prior
	// authenticated session can't make a failed attempt look successful.
	if params.IsolateSession {
		_ = network.ClearCookies(ctx)
	}

	if err := chromedp.Run(ctx,
		chromedp.Navigate(params.URL),
		chromedp.WaitReady("body"),
	); err != nil {
		return nil, fmt.Errorf("navigate to login page: %w", err)
	}

	fields, _ := dom.GetFormFields(ctx, "form")
	result.FormFields = fields

	actions := []chromedp.Action{
		chromedp.WaitVisible(params.UsernameSelector),
		chromedp.Clear(params.UsernameSelector),
		chromedp.SendKeys(params.UsernameSelector, params.Username),
		chromedp.Clear(params.PasswordSelector),
		chromedp.SendKeys(params.PasswordSelector, params.Password),
	}

	for selector, value := range params.ExtraFields {
		actions = append(actions,
			chromedp.Clear(selector),
			chromedp.SendKeys(selector, value),
		)
	}

	if err := chromedp.Run(ctx, actions...); err != nil {
		return nil, fmt.Errorf("fill login form: %w", err)
	}

	// Snapshot the cookie jar right before submitting, to detect whether the
	// login establishes or rotates a session cookie.
	beforeCookies := cookieValues(ctx)

	if err := chromedp.Run(ctx, chromedp.Click(params.SubmitSelector)); err != nil {
		return nil, fmt.Errorf("submit login form: %w", err)
	}

	// Wait for the post-submit navigation/AJAX to settle instead of a fixed
	// sleep — bounded so a hung request can't block forever.
	_, _ = wait.For(ctx, wait.Condition{NetworkIdle: true, TimeoutMs: 8000}, mon.InFlight)

	var currentURL string
	chromedp.Run(ctx, chromedp.Location(&currentURL))
	result.FinalURL = currentURL

	afterCookies, _ := network.GetCookies(ctx)
	for _, c := range afterCookies {
		result.Cookies = append(result.Cookies, CookieInfo{
			Name:     c.Name,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
			SameSite: string(c.SameSite),
		})
	}

	evaluateLogin(ctx, result, params, currentURL, beforeCookies)

	if !result.Success && result.ErrorMsg == "" {
		result.ErrorMsg = "login appears to have failed: " + result.Reason
	}

	return result, nil
}

// evaluateLogin decides whether the login succeeded. Explicit indicators win;
// otherwise it combines several signals so a mere redirect (e.g. to a setup or
// error page) is NOT mistaken for success.
func evaluateLogin(ctx context.Context, result *LoginResult, params LoginParams, currentURL string, before map[string]string) {
	if params.SuccessIndicator != "" {
		ok := nodeExists(ctx, params.SuccessIndicator)
		result.Success = ok
		result.Confidence = "high"
		if ok {
			result.Reason = "success indicator present"
		} else {
			result.Reason = "success indicator absent"
		}
		return
	}
	if params.FailureIndicator != "" {
		present := nodeExists(ctx, params.FailureIndicator)
		result.Success = !present
		result.Confidence = "high"
		if present {
			result.Reason = "failure indicator present"
		} else {
			result.Reason = "failure indicator absent"
		}
		return
	}

	stillLogin := currentURL == params.URL ||
		strings.Contains(strings.ToLower(currentURL), "login") ||
		pageHasPassword(ctx)
	failWord := firstFailureWord(strings.ToLower(pageText(ctx)))
	sessionChanged := sessionEstablished(ctx, before)
	hasLogout := pageHasLogout(ctx)

	switch {
	case stillLogin:
		result.Success = false
		result.Confidence = "high"
		result.Reason = "final page still presents a login form or login URL"
	case failWord != "":
		result.Success = false
		result.Confidence = "high"
		result.Reason = fmt.Sprintf("failure message present on page (%q)", failWord)
	case sessionChanged || hasLogout:
		result.Success = true
		result.Confidence = "high"
		result.Reason = "left the login page with no login form, and a session was established (new/rotated cookie or logout affordance present)"
	default:
		result.Success = false
		result.Confidence = "low"
		result.Reason = fmt.Sprintf("navigated to %s with no login form, but no session cookie nor logout link was observed — authentication could not be confirmed; pass success_indicator to assert it", currentURL)
	}
}

func nodeExists(ctx context.Context, selector string) bool {
	var nodes []*cdp.Node
	if err := chromedp.Run(ctx, chromedp.Nodes(selector, &nodes, chromedp.AtLeast(0))); err != nil {
		return false
	}
	return len(nodes) > 0
}

func cookieValues(ctx context.Context) map[string]string {
	m := map[string]string{}
	cookies, err := network.GetCookies(ctx)
	if err != nil {
		return m
	}
	for _, c := range cookies {
		m[c.Name] = c.Value
	}
	return m
}

// sessionEstablished reports whether any session-like cookie was added or
// changed compared to the pre-submit snapshot.
func sessionEstablished(ctx context.Context, before map[string]string) bool {
	cookies, err := network.GetCookies(ctx)
	if err != nil {
		return false
	}
	for _, c := range cookies {
		if !isSessionCookie(c.Name, c.HTTPOnly) {
			continue
		}
		if prev, ok := before[c.Name]; !ok || prev != c.Value {
			return true
		}
	}
	return false
}

func isSessionCookie(name string, httpOnly bool) bool {
	if httpOnly {
		return true
	}
	n := strings.ToLower(name)
	for _, h := range []string{"sess", "sid", "token", "auth", "jwt", "remember", "login"} {
		if strings.Contains(n, h) {
			return true
		}
	}
	return false
}

func pageHasPassword(ctx context.Context) bool {
	var n int
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.querySelectorAll('input[type="password"]').length`, &n)); err != nil {
		return false
	}
	return n > 0
}

func pageHasLogout(ctx context.Context) bool {
	var has bool
	expr := `(function(){
		if (document.querySelector('a[href*="logout" i], a[href*="signout" i], a[href*="logoff" i], a[href*="deconnexion" i]')) return true;
		var t = document.body ? document.body.innerText : "";
		return /\b(log\s?out|sign\s?out|log\s?off|déconnexion|déconnecter|sign\s?off)\b/i.test(t);
	})()`
	if err := chromedp.Run(ctx, chromedp.Evaluate(expr, &has)); err != nil {
		return false
	}
	return has
}

func pageText(ctx context.Context) string {
	var s string
	chromedp.Run(ctx, chromedp.Evaluate(`(document.body ? document.body.innerText : "").slice(0, 4000)`, &s))
	return s
}

func firstFailureWord(loweredText string) string {
	for _, w := range []string{
		"incorrect", "invalid", "failed", "wrong", "denied",
		"try again", "bad credential", "authentication failed", "not recognized",
	} {
		if strings.Contains(loweredText, w) {
			return w
		}
	}
	return ""
}

func CheckSession(ctx context.Context, protectedURL string) (bool, error) {
	var statusCode int64
	mon := network.NewMonitor()
	if err := mon.Start(ctx); err != nil {
		return false, err
	}
	defer mon.Stop()

	if err := chromedp.Run(ctx,
		chromedp.Navigate(protectedURL),
		chromedp.WaitReady("body"),
	); err != nil {
		return false, err
	}

	var currentURL string
	chromedp.Run(ctx, chromedp.Location(&currentURL))

	entries := mon.GetEntries()
	for _, e := range entries {
		if e.URL == protectedURL {
			statusCode = e.Status
			break
		}
	}

	return statusCode >= 200 && statusCode < 400 && currentURL == protectedURL, nil
}
