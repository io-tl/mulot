package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/io-tl/mulot/internal/auth"
	"github.com/io-tl/mulot/internal/browser"
	"github.com/io-tl/mulot/internal/dom"
	"github.com/io-tl/mulot/internal/fuzz"
	"github.com/io-tl/mulot/internal/httpx"
	"github.com/io-tl/mulot/internal/journal"
	"github.com/io-tl/mulot/internal/js"
	"github.com/io-tl/mulot/internal/navigation"
	"github.com/io-tl/mulot/internal/network"
	"github.com/io-tl/mulot/internal/security"
	"github.com/io-tl/mulot/internal/wait"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type session struct {
	browser *browser.Browser
	tab     *browser.Tab
	netMon  *network.Monitor
	console *js.ConsoleCapture
	dialogs *browser.DialogHandler
	journal *journal.Journal
}

func Run() error {
	s := server.NewMCPServer(
		"mulot",
		"0.1.0",
		server.WithToolCapabilities(false),
	)

	sess := &session{}

	registerTools(s, sess)

	return server.ServeStdio(s)
}

func jsonResult(v any) (*mcp.CallToolResult, error) {
	// A nil slice marshals to `null`, which is ambiguous to an agent (error?
	// not run? empty?). Normalize it to an empty list so "nothing found"
	// reads as `[]`.
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Slice && rv.IsNil() {
		v = []any{}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(b)), nil
}

func errResult(msg string) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: msg},
		},
		IsError: true,
	}, nil
}

// buildBaseRequest assembles an httpx.Request from tool arguments, shared by
// http_request and http_fuzz. An optional from_flow seeds method/url/headers/body
// from a journaled exchange; explicit fields then OVERRIDE the flow (fields win
// over flow). Session cookies are added unless use_session=false.
func buildBaseRequest(sess *session, args map[string]any) (httpx.Request, error) {
	var r httpx.Request

	if f, ok := args["from_flow"].(float64); ok && f != 0 {
		if sess.journal == nil {
			return r, fmt.Errorf("no traffic journal — call browser_launch first")
		}
		rd, err := sess.journal.ForReplay(int64(f))
		if err != nil {
			return r, fmt.Errorf("flow %d not found: %v", int64(f), err)
		}
		r.Method, r.URL, r.Headers, r.Body = rd.Method, rd.URL, rd.Headers, rd.Body
	}

	// Explicit fields override the flow base.
	if v, ok := args["url"].(string); ok && v != "" {
		r.URL = v
	}
	if v, ok := args["method"].(string); ok && v != "" {
		r.Method = v
	}
	if v, ok := args["body"].(string); ok {
		r.Body = v
	}
	for k, v := range argStringMap(args["headers"]) {
		if r.Headers == nil {
			r.Headers = map[string]string{}
		}
		r.Headers[k] = v
	}
	if f, ok := args["follow_redirects"].(bool); ok {
		r.FollowRedirects = f
	}
	if t, ok := args["timeout_ms"].(float64); ok {
		r.TimeoutMs = int(t)
	}

	if r.URL == "" {
		return r, fmt.Errorf("url is required (or a valid from_flow)")
	}

	useSession := true
	if s, ok := args["use_session"].(bool); ok {
		useSession = s
	}
	if useSession && sess.tab != nil {
		r.Cookies = append(r.Cookies, sessionCookiesFor(sess.tab.Context(), r.URL)...)
	}
	for k, v := range argStringMap(args["cookies"]) {
		r.Cookies = append(r.Cookies, &http.Cookie{Name: k, Value: v})
	}
	return r, nil
}

func registerTools(s *server.MCPServer, sess *session) {

	// ── Lifecycle ──────────────────────────────────────────────

	s.AddTool(
		mcp.NewTool("browser_launch",
			mcp.WithDescription("Start a Chromium browser. MUST be called before any other browser_ tool. Auto-starts network/console/dialog monitoring and the always-on HTTP traffic journal (SQLite). Calling again closes the previous instance."),
			mcp.WithBoolean("headless", mcp.Description("Run without visible UI (default: true). Set false for visual debugging.")),
			mcp.WithString("proxy", mcp.Description("Upstream HTTP/SOCKS5 proxy to route the browser through, e.g. 'http://127.0.0.1:8080' (Burp) or 'socks5://127.0.0.1:9050' (Tor).")),
			mcp.WithString("journal_db", mcp.Description("Path to the SQLite traffic journal (default: ~/.mulot/traffic.db). The journal records every request/response automatically.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()

			if sess.browser != nil {
				sess.browser.Close()
			}

			opts := []browser.Option{browser.WithHeadless(true)}
			if h, ok := args["headless"].(bool); ok {
				opts = []browser.Option{browser.WithHeadless(h)}
			}
			if p, ok := args["proxy"].(string); ok && p != "" {
				opts = append(opts, browser.WithProxy(p))
			}

			b := browser.New(opts...)
			if err := b.Start(ctx); err != nil {
				return errResult(fmt.Sprintf("failed to launch browser: %v", err))
			}

			tab, err := b.NewTab(ctx)
			if err != nil {
				b.Close()
				return errResult(fmt.Sprintf("failed to create tab: %v", err))
			}

			sess.browser = b
			sess.tab = tab
			sess.netMon = network.NewMonitor()
			sess.netMon.Start(tab.Context())
			sess.console = js.NewConsoleCapture()
			sess.console.Start(tab.Context())
			sess.dialogs = browser.NewDialogHandler("accept")
			sess.dialogs.Start(tab.Context())

			dbPath, _ := args["journal_db"].(string)
			msg := "Browser launched successfully"
			if jr, err := journal.Open(dbPath); err != nil {
				msg += fmt.Sprintf(" (traffic journal disabled: %v)", err)
			} else {
				jr.Start(tab.Context())
				sess.journal = jr
				msg += " — traffic journal at " + jr.Path()
			}

			return mcp.NewToolResultText(msg), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_close",
			mcp.WithDescription("Shut down the browser and release all resources. Call when done with browser automation."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.browser == nil {
				return mcp.NewToolResultText("No browser running"), nil
			}
			if sess.netMon != nil {
				sess.netMon.Stop()
			}
			if sess.console != nil {
				sess.console.Stop()
			}
			if sess.dialogs != nil {
				sess.dialogs.Stop()
			}
			// Close the journal before the browser so queued body fetches can
			// still reach the live CDP connection.
			if sess.journal != nil {
				sess.journal.Close()
			}
			sess.browser.Close()
			sess.browser = nil
			sess.tab = nil
			sess.netMon = nil
			sess.console = nil
			sess.dialogs = nil
			sess.journal = nil
			return mcp.NewToolResultText("Browser closed"), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_health_check",
			mcp.WithDescription("Test if the browser process is alive and responsive. Returns {healthy: bool}. Use when other tools return unexpected errors to check if the browser crashed."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.browser == nil {
				return errResult("browser not launched")
			}
			if err := sess.browser.HealthCheck(ctx); err != nil {
				return jsonResult(map[string]any{"healthy": false, "error": err.Error()})
			}
			return jsonResult(map[string]any{"healthy": true})
		},
	)

	// ── Navigation ─────────────────────────────────────────────

	s.AddTool(
		mcp.NewTool("browser_navigate",
			mcp.WithDescription("Load a URL and wait for the page to be ready. Returns {url, title} — compare url to detect redirects. Call browser_snapshot after to read page content."),
			mcp.WithString("url", mcp.Required(), mcp.Description("Full URL with protocol, e.g. 'https://example.com/login'")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched — call browser_launch first")
			}
			url, _ := req.GetArguments()["url"].(string)
			if url == "" {
				return errResult("url is required")
			}
			if err := sess.tab.Run(
				chromedp.Navigate(url),
				chromedp.WaitReady("body"),
			); err != nil {
				return errResult(fmt.Sprintf("navigation failed: %v", err))
			}
			var title string
			chromedp.Run(sess.tab.Context(), chromedp.Title(&title))
			var currentURL string
			chromedp.Run(sess.tab.Context(), chromedp.Location(&currentURL))
			return jsonResult(map[string]string{"url": currentURL, "title": title})
		},
	)

	s.AddTool(
		mcp.NewTool("browser_go_back",
			mcp.WithDescription("Go back one step in browser history."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			if err := sess.tab.Run(chromedp.NavigateBack()); err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			return mcp.NewToolResultText("Navigated back"), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_go_forward",
			mcp.WithDescription("Go forward one step in browser history."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			if err := sess.tab.Run(chromedp.NavigateForward()); err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			return mcp.NewToolResultText("Navigated forward"), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_reload",
			mcp.WithDescription("Reload the current page and wait for it to be ready."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			if err := sess.tab.Run(chromedp.Reload()); err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			return mcp.NewToolResultText("Page reloaded"), nil
		},
	)

	// ── Synchronization ────────────────────────────────────────

	s.AddTool(
		mcp.NewTool("browser_wait_for",
			mcp.WithDescription("Wait until the page reaches an expected state, then return {satisfied, elapsedMs, url, title}. ESSENTIAL after browser_click/browser_type, which are non-blocking, before reading the page — otherwise browser_snapshot may show the old page. Specify one or more conditions (all must hold). With no conditions, waits for the document to settle (ready + network idle). Returns an error on timeout."),
			mcp.WithString("selector", mcp.Description("CSS selector (or '[data-mulot-ref=\"e7\"]') to wait on, combined with 'state'.")),
			mcp.WithString("state", mcp.Description("Expected state of 'selector': 'visible' (default), 'hidden', 'present' (in DOM), or 'absent'.")),
			mcp.WithString("text", mcp.Description("Wait until this text appears anywhere in the page's visible text.")),
			mcp.WithString("url_contains", mcp.Description("Wait until the current URL contains this substring (e.g. detect a redirect after login).")),
			mcp.WithBoolean("network_idle", mcp.Description("Wait until there are no in-flight network requests (good after AJAX). Note: pages with SSE/websockets never go idle.")),
			mcp.WithNumber("timeout_ms", mcp.Description("Maximum time to wait in milliseconds (default: 10000).")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			cond := wait.Condition{}
			cond.Selector, _ = args["selector"].(string)
			cond.State, _ = args["state"].(string)
			cond.Text, _ = args["text"].(string)
			cond.URLContains, _ = args["url_contains"].(string)
			if ni, ok := args["network_idle"].(bool); ok {
				cond.NetworkIdle = ni
			}
			if t, ok := args["timeout_ms"].(float64); ok {
				cond.TimeoutMs = int(t)
			}

			var inFlight wait.InFlightFunc
			if sess.netMon != nil {
				inFlight = sess.netMon.InFlight
			}

			result, err := wait.For(sess.tab.Context(), cond, inFlight)
			if err != nil {
				return errResult(err.Error())
			}
			return jsonResult(result)
		},
	)

	// ── Observation ────────────────────────────────────────────

	s.AddTool(
		mcp.NewTool("browser_snapshot",
			mcp.WithDescription("PRIMARY observation tool. Returns a compact overview: URL, title, cookies, and a list of interactive elements (buttons, links, inputs, headings). Each element has a 'ref' (e.g. 'e7') you can pass DIRECTLY to browser_click/browser_type — no browser_query_dom needed. Call after navigate/click/type to see the new page state. Refs are valid until the next snapshot or navigation. For visual layout, use browser_screenshot instead."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			tctx := sess.tab.Context()

			elements, truncated, err := dom.GetInteractive(tctx, 200)
			if err != nil {
				return errResult(fmt.Sprintf("failed to read page elements: %v", err))
			}

			var title, url string
			chromedp.Run(tctx, chromedp.Title(&title))
			chromedp.Run(tctx, chromedp.Location(&url))

			cookies, _ := network.GetCookies(tctx)
			cookieNames := make([]string, 0, len(cookies))
			for _, c := range cookies {
				cookieNames = append(cookieNames, c.Name)
			}

			result := map[string]any{
				"url":      url,
				"title":    title,
				"cookies":  cookieNames,
				"elements": elements,
			}
			if truncated {
				result["truncated"] = "element list capped at 200; use browser_query_dom for the rest"
			}
			return jsonResult(result)
		},
	)

	s.AddTool(
		mcp.NewTool("browser_screenshot",
			mcp.WithDescription("Capture a PNG screenshot of the full page or a specific element. Use for visual verification, layout checks, or reading rendered text. For finding interactive elements to click/type, prefer browser_snapshot (structured text is faster to process)."),
			mcp.WithString("selector", mcp.Description("CSS selector to capture only that element, e.g. '#main-content', '.modal'. Omit for full page.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			var buf []byte
			sel, _ := req.GetArguments()["selector"].(string)
			if sel != "" {
				if err := sess.tab.Run(chromedp.Screenshot(sel, &buf, chromedp.ByQuery)); err != nil {
					return errResult(fmt.Sprintf("screenshot failed: %v", err))
				}
			} else {
				if err := sess.tab.Run(chromedp.FullScreenshot(&buf, 90)); err != nil {
					return errResult(fmt.Sprintf("screenshot failed: %v", err))
				}
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.ImageContent{
						Type:     "image",
						Data:     encodeBase64(buf),
						MIMEType: "image/png",
					},
				},
			}, nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_query_dom",
			mcp.WithDescription("Query DOM elements by CSS selector. Returns each match's tag, id, classes, all attributes, textContent, visibility, and bounding box. Best tool for inspecting specific elements or discovering the exact CSS selector to pass to browser_click/browser_type."),
			mcp.WithString("selector", mcp.Required(), mcp.Description("CSS selector, e.g. 'button', '.modal input', 'a[href*=\"login\"]', '#search-form *'")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			sel, _ := req.GetArguments()["selector"].(string)
			elements, err := dom.Query(sess.tab.Context(), sel)
			if err != nil {
				return errResult(fmt.Sprintf("query failed: %v", err))
			}
			return jsonResult(elements)
		},
	)

	s.AddTool(
		mcp.NewTool("browser_get_form_fields",
			mcp.WithDescription("List all input, select, and textarea fields inside a container. Returns each field's type, name, current value, placeholder, required flag, and a ready-to-use CSS selector. Call before filling forms to discover field selectors for browser_type."),
			mcp.WithString("selector", mcp.Description("CSS selector of the container to scan (default: 'body' — all fields on the page). E.g. '.login-form', '#checkout', '.modal'")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			sel, _ := req.GetArguments()["selector"].(string)
			if sel == "" {
				sel = "body"
			}
			fields, err := dom.GetFormFields(sess.tab.Context(), sel)
			if err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			return jsonResult(fields)
		},
	)

	// ── Interaction ────────────────────────────────────────────

	s.AddTool(
		mcp.NewTool("browser_click",
			mcp.WithDescription("Click an element. Pass either 'ref' (from browser_snapshot, preferred) or a raw CSS 'selector'. Non-blocking: returns immediately even if the click triggers navigation or AJAX — follow with browser_wait_for to synchronize, then browser_snapshot to see the result."),
			mcp.WithString("ref", mcp.Description("Element ref from browser_snapshot, e.g. 'e7'. Preferred over selector.")),
			mcp.WithString("selector", mcp.Description("CSS selector, e.g. '#login-btn', 'a[href=\"/next\"]', 'input[type=\"submit\"]'. Use when you don't have a snapshot ref.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			sel, err := resolveTarget(req.GetArguments())
			if err != nil {
				return errResult(err.Error())
			}
			jsClick := fmt.Sprintf(`(function(){
				var el = document.querySelector(%q);
				if (!el) return "not_found";
				el.click();
				return "ok";
			})()`, sel)
			var result string
			if err := chromedp.Run(sess.tab.Context(), chromedp.Evaluate(jsClick, &result)); err != nil {
				return errResult(fmt.Sprintf("click failed: %v", err))
			}
			if result == "not_found" {
				return errResult(fmt.Sprintf("click failed: no element matches selector %q", sel))
			}
			return mcp.NewToolResultText(fmt.Sprintf("Clicked: %s", sel)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_type",
			mcp.WithDescription("Type text into a form field. Pass either 'ref' (from browser_snapshot, preferred) or a raw CSS 'selector'. Sends real keyboard events (works with React, Vue, etc.). Clears existing content by default. Use browser_get_form_fields or browser_snapshot to find the field first."),
			mcp.WithString("ref", mcp.Description("Element ref from browser_snapshot, e.g. 'e7'. Preferred over selector.")),
			mcp.WithString("selector", mcp.Description("CSS selector of the input/textarea, e.g. 'input[name=\"email\"]', '#password'. Use when you don't have a snapshot ref.")),
			mcp.WithString("text", mcp.Required(), mcp.Description("Text to type into the field")),
			mcp.WithBoolean("clear", mcp.Description("Clear existing content before typing (default: true). Set false to append.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			sel, err := resolveTarget(args)
			if err != nil {
				return errResult(err.Error())
			}
			text, _ := args["text"].(string)
			clear := true
			if c, ok := args["clear"].(bool); ok {
				clear = c
			}
			tctx := sess.tab.Context()
			// JS-based clear works on empty fields (chromedp.Clear errors with
			// "does not have child #text node") and on framework-controlled inputs.
			if clear {
				if err := dom.ClearField(tctx, sel); err != nil {
					return errResult(fmt.Sprintf("type failed: %v", err))
				}
			}
			if err := chromedp.Run(tctx, chromedp.SendKeys(sel, text)); err != nil {
				return errResult(fmt.Sprintf("type failed: %v", err))
			}
			return mcp.NewToolResultText(fmt.Sprintf("Typed into: %s", sel)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_select",
			mcp.WithDescription("Choose an option in a <select> dropdown by its value or visible label. Dispatches input/change events so JS frameworks react. Use this for dropdowns — browser_type does not work on <select>."),
			mcp.WithString("ref", mcp.Description("Element ref from browser_snapshot, e.g. 'e7'. Preferred over selector.")),
			mcp.WithString("selector", mcp.Description("CSS selector of the <select>, e.g. 'select[name=\"country\"]', '#security'.")),
			mcp.WithString("value", mcp.Required(), mcp.Description("The option's value attribute OR its visible text, e.g. 'low', 'United States'.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			sel, err := resolveTarget(args)
			if err != nil {
				return errResult(err.Error())
			}
			value, _ := args["value"].(string)
			if err := dom.SelectOption(sess.tab.Context(), sel, value); err != nil {
				return errResult(fmt.Sprintf("select failed: %v", err))
			}
			return mcp.NewToolResultText(fmt.Sprintf("Selected %q in %s", value, sel)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_upload_file",
			mcp.WithDescription("Attach a file to a file <input type=\"file\"> so the next form submit uploads it. Provide the file either by 'path' (existing file on this machine) or by 'filename'+'content' (written to a temp file first — use this to craft a payload, e.g. a webshell, for authorized file-upload testing). After this, click the form's submit button."),
			mcp.WithString("selector", mcp.Required(), mcp.Description("CSS selector of the file input, e.g. 'input[type=\"file\"]', 'input[name=\"uploaded\"]'.")),
			mcp.WithString("path", mcp.Description("Absolute path to an existing file on the host to upload.")),
			mcp.WithString("filename", mcp.Description("Filename to present (extension matters for upload filters), e.g. 'shell.php'. Requires 'content'.")),
			mcp.WithString("content", mcp.Description("File contents to write to a temp file and upload. Requires 'filename'.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			sel, _ := args["selector"].(string)
			if sel == "" {
				return errResult("selector is required")
			}
			path, _ := args["path"].(string)
			if path == "" {
				filename, _ := args["filename"].(string)
				content, hasContent := args["content"].(string)
				if filename == "" || !hasContent {
					return errResult("provide either 'path', or both 'filename' and 'content'")
				}
				p, err := writeTempUpload(filename, content)
				if err != nil {
					return errResult(fmt.Sprintf("could not stage upload file: %v", err))
				}
				path = p
			}
			if err := sess.tab.Run(chromedp.SetUploadFiles(sel, []string{path}, chromedp.ByQuery)); err != nil {
				return errResult(fmt.Sprintf("upload failed: %v", err))
			}
			return mcp.NewToolResultText(fmt.Sprintf("Attached %s to %s — now click the submit button to upload", path, sel)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_scroll",
			mcp.WithDescription("Scroll the viewport vertically. Use to reveal content below the fold before taking a snapshot or screenshot."),
			mcp.WithString("direction", mcp.Required(), mcp.Description("'up' or 'down'")),
			mcp.WithNumber("pixels", mcp.Description("Scroll distance in pixels (default: 500)")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			dir, _ := args["direction"].(string)
			px := 500.0
			if p, ok := args["pixels"].(float64); ok {
				px = p
			}
			if dir == "up" {
				px = -px
			}
			if err := sess.tab.Run(
				chromedp.Evaluate(fmt.Sprintf("window.scrollBy(0, %f)", px), nil),
			); err != nil {
				return errResult(fmt.Sprintf("scroll failed: %v", err))
			}
			return mcp.NewToolResultText(fmt.Sprintf("Scrolled %s by %.0f pixels", dir, px)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_evaluate_js",
			mcp.WithDescription("Execute JavaScript in the page context (V8) and return the result as JSON. Awaits Promises, so an async expression resolves before returning — write an `(async()=>{...})()` IIFE that loops in-page with fetch() and Promise.all to brute-force/fuzz at speed in ONE call, returning only the hits (no per-iteration MCP or CDP round-trip). Same-origin fetch automatically carries the session cookies. For cross-origin or forbidden headers (Host, Cookie swap), use http_request instead.\n\nThis is also the universal ENCODER/DECODER/CRYPTO (it replaces a fixed decoder menu): base64 atob/btoa, URL encode/decodeURIComponent, hex/bytes via Uint8Array & TextEncoder, JWT (split on '.' then atob), and `await crypto.subtle` for SHA/HMAC/AES. atob/btoa are latin1, so for raw bytes use this helper:\n  const b2h=u=>[...u].map(b=>b.toString(16).padStart(2,'0')).join(''), h2b=h=>new Uint8Array(h.match(/../g).map(x=>parseInt(x,16))), b2b64=u=>btoa(String.fromCharCode(...u)), b642b=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));\nNote: crypto.subtle is undefined outside a secure context (an http:// non-localhost page), so pure byte math (XOR, padding-oracle forging) works anywhere but local hashing/AES needs a secure context (e.g. evaluate on about:blank). Also the escape hatch for localStorage, page APIs, and DOM work CSS selectors can't express."),
			mcp.WithString("expression", mcp.Required(), mcp.Description("JavaScript expression to evaluate (may be async / return a Promise). Return value is JSON-serialized; keep it small (return only matches/aggregates, not every response).")),
			mcp.WithNumber("timeout_ms", mcp.Description("Max time to wait for the expression/Promise (default: 30000). Raise it for large in-page fuzz loops.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			expr, _ := args["expression"].(string)
			timeout := 30 * time.Second
			if t, ok := args["timeout_ms"].(float64); ok && t > 0 {
				timeout = time.Duration(t) * time.Millisecond
			}
			tctx, cancel := context.WithTimeout(sess.tab.Context(), timeout)
			defer cancel()
			result, err := js.Evaluate(tctx, expr)
			if err != nil {
				return errResult(fmt.Sprintf("JS evaluation failed: %v", err))
			}
			return jsonResult(result)
		},
	)

	// ── Debugging ──────────────────────────────────────────────

	s.AddTool(
		mcp.NewTool("browser_get_console",
			mcp.WithDescription("Get console output (log/warn/error/info) and JS exceptions captured since browser launch. Use to debug page issues, verify API behavior, or check for runtime errors. Filter by level to focus on errors only."),
			mcp.WithString("level", mcp.Description("Filter by level: 'log', 'warn', 'error', 'info'. Omit for all entries.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.console == nil {
				return errResult("browser not launched")
			}
			level, _ := req.GetArguments()["level"].(string)
			if level != "" {
				return jsonResult(sess.console.GetEntriesByLevel(level))
			}
			return jsonResult(sess.console.GetEntries())
		},
	)

	// ── Raw HTTP (the generic pentest primitive) ───────────────

	s.AddTool(
		mcp.NewTool("http_request",
			mcp.WithDescription("Send a raw HTTP request and return the full response (status, headers, set-cookie, body) — the Burp-Repeater primitive. Runs OUTSIDE the browser's CORS/same-origin rules, so you get full control over method, headers, and body, and you read any response. Build it from scratch (url) OR seed it from a captured exchange (from_flow, from http_history) and override parts — explicit fields win over the flow. By default it carries the browser's current session cookies (use_session) and does NOT follow redirects (so you see 3xx + Location). Compose it to test IDOR (change an id, swap cookies), access control (replay an admin request as a low-priv user), CORS (set Origin, read Access-Control-Allow-Origin), SSRF (submit an internal URL, observe), JWT/auth tampering, forced browsing, and HTTP method abuse. The model supplies the methodology; this tool is the mechanism."),
			mcp.WithString("url", mcp.Description("Full target URL, e.g. 'http://localhost:4280/vulnerabilities/sqli/?id=1'. Required unless from_flow is given.")),
			mcp.WithNumber("from_flow", mcp.Description("Seed the request from a captured exchange (the id from http_history). Other fields override it.")),
			mcp.WithString("method", mcp.Description("HTTP method (default GET): GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD...")),
			mcp.WithObject("headers", mcp.Description("Request headers as a JSON object, e.g. {\"Origin\":\"https://evil.com\",\"X-Forwarded-For\":\"127.0.0.1\"}. Merged over the flow's headers when from_flow is used.")),
			mcp.WithString("body", mcp.Description("Raw request body (set Content-Type via headers), e.g. 'username=admin&password=x'.")),
			mcp.WithObject("cookies", mcp.Description("Explicit cookies to send as a JSON object {name: value}. Use to replay as another identity/role (combine with use_session=false).")),
			mcp.WithBoolean("use_session", mcp.Description("Also send the browser's current cookies for this host (default: true). Set false to send an unauthenticated or fully custom request.")),
			mcp.WithBoolean("follow_redirects", mcp.Description("Follow 3xx redirects (default: false — you usually want to inspect the redirect itself).")),
			mcp.WithNumber("timeout_ms", mcp.Description("Request timeout in milliseconds (default: 15000).")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			r, err := buildBaseRequest(sess, req.GetArguments())
			if err != nil {
				return errResult(err.Error())
			}
			resp, err := httpx.Send(ctx, r)
			if err != nil {
				return errResult(fmt.Sprintf("request failed: %v", err))
			}
			return jsonResult(resp)
		},
	)

	// ── Fuzzing (Burp-Intruder "sniper") ───────────────────────

	s.AddTool(
		mcp.NewTool("http_fuzz",
			mcp.WithDescription("Burp-Intruder 'sniper': take a base request containing a marker token (default 'FUZZ'), substitute each payload in turn, send it (outside CORS), and return one row per payload {payload, status, length, timeMs, matched}. The marker is replaced in the URL, body, header values, and cookie values. Build the base from scratch (url) or from a captured exchange (from_flow). Use it to generalize what you'd do one-by-one in http_request: SQLi (error and boolean-blind via length/status deltas), forced browsing / directory & file discovery, parameter and value fuzzing, brute force. Supply match_status/match_regex to flag hits; otherwise read the status/length columns yourself to spot anomalies. Sequential, single marker, max 500 payloads per call (split into batches beyond that). For DOM-XSS execution proof use scan_xss instead — this tool only sees raw HTTP."),
			mcp.WithArray("payloads", mcp.Required(), mcp.Description("Payload values to substitute for the marker, e.g. [\"1' AND '1'='1\",\"1' AND '1'='2\"] or a wordlist of paths. Max 500."), mcp.Items(map[string]any{"type": "string"})),
			mcp.WithString("marker", mcp.Description("Token replaced by each payload (default 'FUZZ'). Place it where you want to inject, e.g. url '.../?id=FUZZ'.")),
			mcp.WithString("url", mcp.Description("Base URL containing the marker, e.g. 'http://host/?id=FUZZ'. Required unless from_flow is given.")),
			mcp.WithNumber("from_flow", mcp.Description("Seed the base request from a captured exchange (id from http_history); put the marker in an overridden field.")),
			mcp.WithString("method", mcp.Description("HTTP method (default GET).")),
			mcp.WithObject("headers", mcp.Description("Base request headers (JSON object). The marker is substituted in header values.")),
			mcp.WithString("body", mcp.Description("Base request body; put the marker here to fuzz a POST parameter, e.g. 'user=admin&pass=FUZZ'.")),
			mcp.WithObject("cookies", mcp.Description("Explicit cookies (JSON object); the marker is substituted in cookie values.")),
			mcp.WithBoolean("use_session", mcp.Description("Also send the browser's current cookies (default: true).")),
			mcp.WithBoolean("follow_redirects", mcp.Description("Follow 3xx redirects (default: false).")),
			mcp.WithNumber("match_status", mcp.Description("Flag rows whose response status equals this, e.g. 200 for forced browsing.")),
			mcp.WithString("match_regex", mcp.Description("Flag rows whose response body matches this regular expression, e.g. 'SQL syntax|PDOException'.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			r, err := buildBaseRequest(sess, args)
			if err != nil {
				return errResult(err.Error())
			}
			p := fuzz.Params{Base: r}
			p.Marker, _ = args["marker"].(string)
			p.MatchRegex, _ = args["match_regex"].(string)
			if v, ok := args["match_status"].(float64); ok {
				p.MatchStatus = int(v)
			}
			if raw, ok := args["payloads"].([]any); ok {
				for _, pv := range raw {
					if s, ok := pv.(string); ok {
						p.Payloads = append(p.Payloads, s)
					}
				}
			}
			out, err := fuzz.Run(ctx, p)
			if err != nil {
				return errResult(fmt.Sprintf("fuzz failed: %v", err))
			}
			return jsonResult(out)
		},
	)

	// ── Traffic journal (always-on, SQLite) ───────────────────

	s.AddTool(
		mcp.NewTool("http_history",
			mcp.WithDescription("Query the always-on HTTP traffic journal (every request/response since launch, persisted to SQLite) — the Burp Proxy history. Returns flow metadata (id, method, url, host, status, mimeType, sizes, timing) — newest first. Use the filters to narrow down, then http_flow_body for a specific body, http_flow for headers, or http_request/http_fuzz with from_flow to re-issue one. Bodies are stored only for text-like responses."),
			mcp.WithString("host", mcp.Description("Exact host filter, e.g. 'app.example.com'.")),
			mcp.WithString("method", mcp.Description("HTTP method filter, e.g. 'POST'.")),
			mcp.WithNumber("status", mcp.Description("Exact status code, e.g. 200.")),
			mcp.WithNumber("status_min", mcp.Description("Minimum status code, e.g. 400 to see only errors.")),
			mcp.WithString("url_contains", mcp.Description("Substring the URL must contain, e.g. '/api/'.")),
			mcp.WithString("body_contains", mcp.Description("Substring that must appear in a stored request/response body, e.g. a token or error string.")),
			mcp.WithNumber("since_id", mcp.Description("Only flows with id greater than this (poll for new traffic).")),
			mcp.WithNumber("limit", mcp.Description("Max rows to return (default 100, max 1000).")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.journal == nil {
				return errResult("no traffic journal — call browser_launch first")
			}
			args := req.GetArguments()
			f := journal.Filter{}
			f.Host, _ = args["host"].(string)
			f.Method, _ = args["method"].(string)
			f.URLContains, _ = args["url_contains"].(string)
			f.BodyContains, _ = args["body_contains"].(string)
			if v, ok := args["status"].(float64); ok {
				f.Status = int(v)
			}
			if v, ok := args["status_min"].(float64); ok {
				f.StatusMin = int(v)
			}
			if v, ok := args["since_id"].(float64); ok {
				f.SinceID = int64(v)
			}
			if v, ok := args["limit"].(float64); ok {
				f.Limit = int(v)
			}
			flows, err := sess.journal.Query(f)
			if err != nil {
				return errResult(fmt.Sprintf("query failed: %v", err))
			}
			return jsonResult(flows)
		},
	)

	s.AddTool(
		mcp.NewTool("http_flow_body",
			mcp.WithDescription("Get the stored request or response body of a journaled flow (by the id from http_history). Returns the body text and whether it was truncated. Bodies are only stored for text-like content."),
			mcp.WithNumber("flow_id", mcp.Required(), mcp.Description("The flow id from http_history.")),
			mcp.WithString("kind", mcp.Description("'response' (default) or 'request'.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.journal == nil {
				return errResult("no traffic journal — call browser_launch first")
			}
			args := req.GetArguments()
			idF, _ := args["flow_id"].(float64)
			kind, _ := args["kind"].(string)
			if kind == "" {
				kind = "response"
			}
			body, truncated, err := sess.journal.Body(int64(idF), kind)
			if err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			if body == nil {
				return jsonResult(map[string]any{"found": false, "kind": kind})
			}
			return jsonResult(map[string]any{
				"found":     true,
				"kind":      kind,
				"truncated": truncated,
				"body":      string(body),
			})
		},
	)

	s.AddTool(
		mcp.NewTool("http_flow",
			mcp.WithDescription("Get a journaled exchange (by the id from http_history) WITH its request and response headers. This is how you read a header the browser saw but doesn't expose to JS — the Location of a 3xx redirect (e.g. an encrypted token passed in a redirect), Set-Cookie, WWW-Authenticate, CSP, or any custom header — without re-issuing the request. Redirect hops are recorded as their own flows, so filter http_history by status (301/302) to find them."),
			mcp.WithNumber("flow_id", mcp.Required(), mcp.Description("The flow id from http_history.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.journal == nil {
				return errResult("no traffic journal — call browser_launch first")
			}
			idF, _ := req.GetArguments()["flow_id"].(float64)
			flow, err := sess.journal.Flow(int64(idF))
			if err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			if flow == nil {
				return jsonResult(map[string]any{"found": false})
			}
			return jsonResult(flow)
		},
	)

	s.AddTool(
		mcp.NewTool("http_clear",
			mcp.WithDescription("Delete all recorded flows and bodies from the traffic journal. Use to start a clean capture before a specific test."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.journal == nil {
				return errResult("no traffic journal — call browser_launch first")
			}
			if err := sess.journal.Clear(); err != nil {
				return errResult(fmt.Sprintf("clear failed: %v", err))
			}
			return mcp.NewToolResultText("Traffic journal cleared"), nil
		},
	)

	// ── Cookies ────────────────────────────────────────────────

	s.AddTool(
		mcp.NewTool("browser_get_cookies",
			mcp.WithDescription("Get all cookies for the current domain. Returns [{name, value, domain, path, expires, httpOnly, secure}]."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			cookies, err := network.GetCookies(sess.tab.Context())
			if err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			return jsonResult(cookies)
		},
	)

	s.AddTool(
		mcp.NewTool("browser_set_cookie",
			mcp.WithDescription("Set a browser cookie. Use to inject auth tokens or session IDs before navigating."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Cookie name")),
			mcp.WithString("value", mcp.Required(), mcp.Description("Cookie value")),
			mcp.WithString("domain", mcp.Required(), mcp.Description("Cookie domain, e.g. '.example.com'")),
			mcp.WithString("path", mcp.Description("Cookie path (default: '/')")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			name, _ := args["name"].(string)
			value, _ := args["value"].(string)
			domain, _ := args["domain"].(string)
			path, _ := args["path"].(string)
			if path == "" {
				path = "/"
			}
			if err := network.SetCookie(sess.tab.Context(), name, value, domain, path); err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			return mcp.NewToolResultText("Cookie set"), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_clear_cookies",
			mcp.WithDescription("Delete all browser cookies. Resets authentication and session state."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			if err := network.ClearCookies(sess.tab.Context()); err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			return mcp.NewToolResultText("Cookies cleared"), nil
		},
	)

	// ── Dialogs ────────────────────────────────────────────────

	s.AddTool(
		mcp.NewTool("browser_handle_dialog",
			mcp.WithDescription("Respond to a pending JS dialog (alert/confirm/prompt). By default, dialogs are auto-accepted — use browser_set_dialog_mode to change this behavior."),
			mcp.WithBoolean("accept", mcp.Description("true to click OK, false to click Cancel (default: true)")),
			mcp.WithString("prompt_text", mcp.Description("Text to enter for prompt() dialogs before accepting")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			accept := true
			if a, ok := args["accept"].(bool); ok {
				accept = a
			}
			promptText, _ := args["prompt_text"].(string)
			if err := browser.HandleDialog(sess.tab.Context(), accept, promptText); err != nil {
				return errResult(fmt.Sprintf("failed: %v", err))
			}
			return mcp.NewToolResultText("Dialog handled"), nil
		},
	)

	s.AddTool(
		mcp.NewTool("browser_get_dialog_events",
			mcp.WithDescription("Get the history of all JS dialogs (alert/confirm/prompt) that appeared since browser launch, with their type, message, and how each was handled."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.dialogs == nil {
				return errResult("browser not launched")
			}
			return jsonResult(sess.dialogs.GetEvents())
		},
	)

	s.AddTool(
		mcp.NewTool("browser_set_dialog_mode",
			mcp.WithDescription("Configure automatic dialog handling: 'accept' (click OK — default), 'dismiss' (click Cancel), 'manual' (dialogs queue until browser_handle_dialog is called)."),
			mcp.WithString("mode", mcp.Required(), mcp.Description("'accept', 'dismiss', or 'manual'")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.dialogs == nil {
				return errResult("browser not launched")
			}
			mode, _ := req.GetArguments()["mode"].(string)
			sess.dialogs.SetMode(mode)
			return mcp.NewToolResultText(fmt.Sprintf("Dialog mode set to: %s", mode)), nil
		},
	)

	// ── Security Testing ───────────────────────────────────────

	s.AddTool(
		mcp.NewTool("scan_login",
			mcp.WithDescription("Automated login flow: navigates, fills username/password, submits, waits for the page to settle, then judges the outcome. Returns {success, confidence, reason, finalUrl, cookies, ...}. Success detection without indicators combines several signals (login form gone, not back on a login URL, a session cookie established/rotated or a logout link present, no failure message) — a bare redirect is NOT treated as success. For reliable verdicts pass success_indicator or failure_indicator. When confidence is 'low', verify manually. Use browser_get_form_fields first to find selectors."),
			mcp.WithString("url", mcp.Required(), mcp.Description("Login page URL, e.g. 'https://app.example.com/login'")),
			mcp.WithString("username_selector", mcp.Required(), mcp.Description("CSS selector for username/email field, e.g. 'input[name=\"email\"]'")),
			mcp.WithString("password_selector", mcp.Required(), mcp.Description("CSS selector for password field, e.g. 'input[type=\"password\"]'")),
			mcp.WithString("submit_selector", mcp.Required(), mcp.Description("CSS selector for submit button, e.g. 'button[type=\"submit\"]'")),
			mcp.WithString("username", mcp.Required(), mcp.Description("Username or email to enter")),
			mcp.WithString("password", mcp.Required(), mcp.Description("Password to enter")),
			mcp.WithString("success_indicator", mcp.Description("CSS selector visible ONLY on successful login, e.g. '.dashboard', 'a[href*=logout]'. Gives a high-confidence verdict.")),
			mcp.WithString("failure_indicator", mcp.Description("CSS selector visible ONLY on failed login, e.g. '.error-message', '.alert-danger'. Gives a high-confidence verdict.")),
			mcp.WithBoolean("isolate_session", mcp.Description("Clear cookies before attempting (default: false). Set true when testing credentials so an existing logged-in session can't produce a false positive.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			params := auth.LoginParams{
				URL:              args["url"].(string),
				UsernameSelector: args["username_selector"].(string),
				PasswordSelector: args["password_selector"].(string),
				SubmitSelector:   args["submit_selector"].(string),
				Username:         args["username"].(string),
				Password:         args["password"].(string),
			}
			if si, ok := args["success_indicator"].(string); ok {
				params.SuccessIndicator = si
			}
			if fi, ok := args["failure_indicator"].(string); ok {
				params.FailureIndicator = fi
			}
			if iso, ok := args["isolate_session"].(bool); ok {
				params.IsolateSession = iso
			}
			result, err := auth.TestLogin(sess.tab.Context(), params)
			if err != nil {
				return errResult(fmt.Sprintf("login test failed: %v", err))
			}
			return jsonResult(result)
		},
	)

	s.AddTool(
		mcp.NewTool("scan_passive",
			mcp.WithDescription("Passive security scan (Burp passive-scanner style), read-only — run after browsing the app. Aggregates three checks and returns {headers, secrets, js}: (1) headers — audits all journaled responses for missing/weak security headers (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy...); (2) secrets — scans the current page DOM for exposed API keys/tokens/passwords, and with include_network also the journaled JSON/JS response bodies; (3) js — static analysis of page JavaScript for dangerous sinks (eval, innerHTML, document.write, postMessage without origin check, unsafe-eval in CSP)."),
			mcp.WithBoolean("include_network", mcp.Description("Also scan journaled response bodies for secrets (default: false). More thorough but slower.")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}

			var views []journal.ResponseView
			if sess.journal != nil {
				v, err := sess.journal.Responses()
				if err != nil {
					return errResult(fmt.Sprintf("journal read failed: %v", err))
				}
				views = v
			}

			headers := security.AuditSecurityHeaders(views)
			if headers == nil {
				headers = []security.HeaderAudit{}
			}

			secrets, err := security.ScanForSecrets(sess.tab.Context())
			if err != nil {
				return errResult(fmt.Sprintf("secret scan failed: %v", err))
			}
			if incNet, ok := req.GetArguments()["include_network"].(bool); ok && incNet {
				secrets = append(secrets, security.ScanForSecretsInNetwork(views)...)
			}
			if secrets == nil {
				secrets = []security.Finding{}
			}

			jsFindings, err := security.AuditJavaScript(sess.tab.Context())
			if err != nil {
				return errResult(fmt.Sprintf("JS audit failed: %v", err))
			}
			if jsFindings == nil {
				jsFindings = []security.Finding{}
			}

			return jsonResult(map[string]any{
				"headers": headers,
				"secrets": secrets,
				"js":      jsFindings,
			})
		},
	)

	s.AddTool(
		mcp.NewTool("scan_xss",
			mcp.WithDescription("Inject XSS payloads into a field, SUBMIT the form, and confirm in the real browser DOM whether they execute (via a non-blocking marker — never alert()). Detects reflected and stored XSS, plus DOM XSS that fires on input. Returns {vulnerable, payloadsTested, findings:[{payload, executed, reflected, context, severity}]}. For authorized testing only. If the form has OTHER required fields (e.g. a name field for a stored-XSS guestbook), fill them with browser_type FIRST, then call this with a single payload. Supply your own 'payloads' for context-specific cases (use 'MARKER' as the JS marker placeholder). Use browser_get_form_fields to find selectors."),
			mcp.WithString("selector", mcp.Required(), mcp.Description("CSS selector of the input/textarea to inject into, e.g. 'input[name=\"name\"]', '#comment'")),
			mcp.WithString("submit_selector", mcp.Description("CSS selector of the submit button. Omit to auto-detect the submit button inside the field's form.")),
			mcp.WithArray("payloads", mcp.Description("Optional custom payloads. Use 'MARKER' where the proof-of-execution token should go, e.g. \"<x onmouseover=window['MARKER']=1>\". Omit for a sensible default set."), mcp.Items(map[string]any{"type": "string"})),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			args := req.GetArguments()
			sel, _ := args["selector"].(string)
			submitSel, _ := args["submit_selector"].(string)
			var payloads []string
			if raw, ok := args["payloads"].([]any); ok {
				for _, p := range raw {
					if s, ok := p.(string); ok {
						payloads = append(payloads, s)
					}
				}
			}
			result, err := security.TestXSS(sess.tab.Context(), sel, submitSel, payloads)
			if err != nil {
				return errResult(fmt.Sprintf("XSS test failed: %v", err))
			}
			return jsonResult(result)
		},
	)

	s.AddTool(
		mcp.NewTool("scan_links",
			mcp.WithDescription("Crawl every <a href> on the current page, fetch each URL, and report status codes, redirects, and broken links. Returns {total, broken, skipped, links: [...]}. Same-page anchors (#) and state-changing links (logout, delete, reset...) are reported as skipped and NOT fetched, so it won't destroy your session. Can be slow on pages with many links."),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if sess.tab == nil {
				return errResult("browser not launched")
			}
			results, err := navigation.CheckLinks(sess.tab.Context())
			if err != nil {
				return errResult(fmt.Sprintf("link check failed: %v", err))
			}
			broken := navigation.GetBrokenLinks(results)
			skipped := 0
			for _, r := range results {
				if r.Skipped {
					skipped++
				}
			}
			return jsonResult(map[string]any{
				"total":   len(results),
				"broken":  len(broken),
				"skipped": skipped,
				"links":   results,
			})
		},
	)
}
