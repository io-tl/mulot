package security

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/io-tl/mulot/internal/network"
)

type Finding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	URL      string `json:"url,omitempty"`
	Detail   string `json:"detail"`
	Selector string `json:"selector,omitempty"`
}

type HeaderAudit struct {
	URL     string            `json:"url"`
	Present map[string]string `json:"present"`
	Missing []string          `json:"missing"`
}

func AuditSecurityHeaders(entries []network.Entry) []HeaderAudit {
	required := []string{
		"content-security-policy",
		"x-content-type-options",
		"x-frame-options",
		"strict-transport-security",
		"referrer-policy",
	}

	headers := network.GetSecurityHeaders(entries)
	var audits []HeaderAudit

	for url, found := range headers {
		audit := HeaderAudit{
			URL:     url,
			Present: found,
		}
		for _, h := range required {
			if _, ok := found[h]; !ok {
				audit.Missing = append(audit.Missing, h)
			}
		}
		audits = append(audits, audit)
	}
	return audits
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?`),
	regexp.MustCompile(`(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})["']?`),
	regexp.MustCompile(`(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["']?(AKIA[0-9A-Z]{16})["']?`),
	regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9/+=]{40})["']?`),
	regexp.MustCompile(`(?i)(github[_-]?token|gh[_-]?token)\s*[:=]\s*["']?(gh[ps]_[a-zA-Z0-9]{36,})["']?`),
	regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9_\-.]{20,})`),
}

func ScanForSecrets(ctx context.Context) ([]Finding, error) {
	var pageSource string
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(`document.documentElement.outerHTML`, &pageSource),
	); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, pat := range secretPatterns {
		matches := pat.FindAllStringSubmatch(pageSource, -1)
		for _, match := range matches {
			findings = append(findings, Finding{
				Type:     "exposed-secret",
				Severity: "high",
				Detail:   fmt.Sprintf("potential secret found: %s=<redacted>", match[1]),
			})
		}
	}
	return findings, nil
}

func ScanForSecretsInNetwork(entries []network.Entry, ctx context.Context) []Finding {
	var findings []Finding
	for _, e := range entries {
		if e.MimeType != "" && !strings.Contains(e.MimeType, "json") && !strings.Contains(e.MimeType, "javascript") {
			continue
		}
		body, err := network.GetResponseBody(ctx, e.RequestID)
		if err != nil {
			continue
		}
		for _, pat := range secretPatterns {
			matches := pat.FindAllStringSubmatch(body, -1)
			for _, match := range matches {
				findings = append(findings, Finding{
					Type:     "exposed-secret-network",
					Severity: "high",
					URL:      e.URL,
					Detail:   fmt.Sprintf("potential secret in response: %s=<redacted>", match[1]),
				})
			}
		}
	}
	return findings
}

type XSSResult struct {
	Vulnerable     bool         `json:"vulnerable"`
	PayloadsTested int          `json:"payloadsTested"`
	Findings       []XSSFinding `json:"findings"`
}

type XSSFinding struct {
	Payload   string `json:"payload"`
	Executed  bool   `json:"executed"`
	Reflected bool   `json:"reflected"`
	Context   string `json:"context,omitempty"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
	Selector  string `json:"selector,omitempty"`
}

// TestXSS injects each payload into a field, SUBMITS the form, and checks
// whether the payload actually executed in the real browser DOM (via a
// non-blocking marker — never alert(), which would freeze the page). This
// catches reflected and stored XSS, which the old "type but don't submit"
// approach missed. It also reports payloads that are reflected unescaped even
// when execution can't be confirmed. The browser is the ground truth here, so
// the agent supplies payloads/contexts and TestXSS confirms execution.
//
// Use "MARKER" as a placeholder in custom payloads for the per-attempt token,
// e.g. `<x onclick="window['MARKER']=1">`.
func TestXSS(ctx context.Context, selector, submitSelector string, payloads []string) (*XSSResult, error) {
	if len(payloads) == 0 {
		payloads = defaultXSSPayloads
	}

	var startURL string
	chromedp.Run(ctx, chromedp.Location(&startURL))

	res := &XSSResult{}
	for i, raw := range payloads {
		marker := fmt.Sprintf("__mulot_xss_%d", i)
		payload := strings.ReplaceAll(raw, "MARKER", marker)

		// Reload a fresh form between payloads (reflected XSS needs a clean
		// page), but NOT before the first one — that preserves any other
		// required fields the caller pre-filled (e.g. a name field for a
		// stored-XSS guestbook).
		if i > 0 {
			chromedp.Run(ctx, chromedp.Navigate(startURL), chromedp.WaitReady("body"))
		}

		if !injectValue(ctx, selector, payload) {
			res.PayloadsTested++
			continue
		}

		// Some DOM-based XSS fires on input, before any submit.
		executed := markerSet(ctx, marker)
		context := ""
		if executed {
			context = "dom-on-input"
		} else {
			submitForm(ctx, selector, submitSelector)
			executed = waitMarker(ctx, marker, 2500*time.Millisecond)
			if executed {
				context = "executed-after-submit"
			}
		}

		reflected, refCtx := checkReflection(ctx, payload)
		if context == "" {
			context = refCtx
		}

		if executed || reflected {
			res.Vulnerable = res.Vulnerable || executed
			f := XSSFinding{
				Payload:   raw,
				Executed:  executed,
				Reflected: reflected,
				Context:   context,
				Selector:  selector,
			}
			if executed {
				f.Severity = "critical"
				f.Detail = "payload executed in the page DOM (marker fired)"
			} else {
				f.Severity = "medium"
				f.Detail = "payload reflected unescaped; execution not confirmed with this payload — try another context"
			}
			res.Findings = append(res.Findings, f)
		}
		res.PayloadsTested++
	}

	// Leave the agent on the clean form page.
	chromedp.Run(ctx, chromedp.Navigate(startURL), chromedp.WaitReady("body"))
	return res, nil
}

// injectValue sets the field's value via the native setter (framework-friendly).
func injectValue(ctx context.Context, selector, payload string) bool {
	script := fmt.Sprintf(`(function(){
		var el = document.querySelector(%s);
		if (!el) return false;
		var proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
		var d = Object.getOwnPropertyDescriptor(proto, 'value');
		if (d && d.set) { d.set.call(el, %s); } else { el.value = %s; }
		el.dispatchEvent(new Event('input', {bubbles: true}));
		return true;
	})()`, jsStr(selector), jsStr(payload), jsStr(payload))
	var ok bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &ok)); err != nil {
		return false
	}
	return ok
}

// submitForm clicks a submit button inside the field's form (so the button's
// name is included in the request — required by handlers that check it), or
// falls back to requestSubmit/submit.
func submitForm(ctx context.Context, selector, submitSelector string) {
	sub := "null"
	if submitSelector != "" {
		sub = jsStr(submitSelector)
	}
	script := fmt.Sprintf(`(function(){
		var el = document.querySelector(%s);
		var sub = %s;
		if (sub) { var b = document.querySelector(sub); if (b) { b.click(); return; } }
		var form = el && (el.form || el.closest('form'));
		if (form) {
			var btn = form.querySelector('[type=submit], button:not([type=button])');
			if (btn) { btn.click(); return; }
			if (form.requestSubmit) { form.requestSubmit(); } else { form.submit(); }
		}
	})()`, jsStr(selector), sub)
	chromedp.Run(ctx, chromedp.Evaluate(script, nil))
}

func markerSet(ctx context.Context, marker string) bool {
	var ok bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(fmt.Sprintf(`!!window[%s]`, jsStr(marker)), &ok)); err != nil {
		return false
	}
	return ok
}

func waitMarker(ctx context.Context, marker string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if markerSet(ctx, marker) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// checkReflection reports whether the raw payload appears unescaped in the page
// HTML and, if so, roughly where (script / attribute / html text).
func checkReflection(ctx context.Context, payload string) (bool, string) {
	var html string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.documentElement.outerHTML`, &html)); err != nil {
		return false, ""
	}
	idx := strings.Index(html, payload)
	if idx < 0 {
		return false, ""
	}
	before := strings.ToLower(html[:idx])
	if strings.LastIndex(before, "<script") > strings.LastIndex(before, "</script") {
		return true, "reflected-in-script"
	}
	if idx > 0 && (html[idx-1] == '"' || html[idx-1] == '\'') {
		return true, "reflected-in-attribute"
	}
	return true, "reflected-in-html"
}

func jsStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

var defaultXSSPayloads = []string{
	`<script>window['MARKER']=1</script>`,
	`<img src=x onerror="window['MARKER']=1">`,
	`"><img src=x onerror="window['MARKER']=1">`,
	`'><img src=x onerror="window['MARKER']=1">`,
	`<svg onload="window['MARKER']=1">`,
	`<body onload="window['MARKER']=1">`,
	`<iframe src="javascript:window['MARKER']=1"></iframe>`,
}

func AuditJavaScript(ctx context.Context) ([]Finding, error) {
	var findings []Finding

	dangerousPatterns := []struct {
		check string
		desc  string
		sev   string
	}{
		{
			check: `(function(){var s=document.querySelectorAll('script');var r=[];s.forEach(function(el){if(el.textContent.match(/eval\s*\(/)){r.push(el.textContent.substring(0,200))}});return JSON.stringify(r)})()`,
			desc:  "eval() usage detected",
			sev:   "medium",
		},
		{
			check: `(function(){var s=document.querySelectorAll('script');var r=[];s.forEach(function(el){if(el.textContent.match(/innerHTML\s*=/)){r.push(el.textContent.substring(0,200))}});return JSON.stringify(r)})()`,
			desc:  "innerHTML assignment detected",
			sev:   "medium",
		},
		{
			check: `(function(){var s=document.querySelectorAll('script');var r=[];s.forEach(function(el){if(el.textContent.match(/document\.write/)){r.push(el.textContent.substring(0,200))}});return JSON.stringify(r)})()`,
			desc:  "document.write() usage detected",
			sev:   "low",
		},
		{
			check: `(function(){var h=document.querySelectorAll('script[src]');var r=[];h.forEach(function(el){var s=el.getAttribute('src');if(!el.integrity&&s&&(s.startsWith('http://')||s.startsWith('//'))){r.push(s)}});return JSON.stringify(r)})()`,
			desc:  "external script without SRI",
			sev:   "medium",
		},
	}

	for _, p := range dangerousPatterns {
		var result string
		if err := chromedp.Run(ctx, chromedp.Evaluate(p.check, &result)); err != nil {
			continue
		}
		if result != "[]" && result != "" {
			findings = append(findings, Finding{
				Type:     "js-audit",
				Severity: p.sev,
				Detail:   p.desc,
			})
		}
	}

	return findings, nil
}
