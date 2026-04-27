// Package httpx sends arbitrary HTTP requests outside the browser's
// same-origin/CORS rules, optionally carrying the browser's session cookies.
// It is the generic primitive the LLM composes to test IDOR, SSRF, CORS,
// JWT/auth tampering, forced browsing, HTTP method abuse, etc. — mulot provides
// the mechanism, the model provides the methodology.
package httpx

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

type Request struct {
	Method          string
	URL             string
	Headers         map[string]string
	Body            string
	Cookies         []*http.Cookie
	FollowRedirects bool
	TimeoutMs       int
}

type Response struct {
	Status        int               `json:"status"`
	StatusText    string            `json:"statusText"`
	Headers       map[string]string `json:"headers"`
	SetCookies    []string          `json:"setCookies,omitempty"`
	Body          string            `json:"body"`
	BodyBytes     int               `json:"bodyBytes"`
	BodyTruncated bool              `json:"bodyTruncated,omitempty"`
	FinalURL      string            `json:"finalUrl,omitempty"`
	Redirected    bool              `json:"redirected,omitempty"`
	ElapsedMs     int64             `json:"elapsedMs"`
}

const maxBody = 20000

// Send performs the request and returns the response. By default it does NOT
// follow redirects, so the caller sees the raw 3xx + Location (important for
// open-redirect and auth-flow analysis).
func Send(ctx context.Context, r Request) (*Response, error) {
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method == "" {
		method = "GET"
	}
	timeout := time.Duration(r.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	for _, c := range r.Cookies {
		req.AddCookie(c)
	}

	client := &http.Client{Timeout: timeout}
	if !r.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	truncated := false
	if len(raw) > maxBody {
		raw = raw[:maxBody]
		truncated = true
	}

	headers := make(map[string]string, len(resp.Header))
	for k, vv := range resp.Header {
		headers[k] = strings.Join(vv, ", ")
	}

	out := &Response{
		Status:        resp.StatusCode,
		StatusText:    resp.Status,
		Headers:       headers,
		SetCookies:    resp.Header["Set-Cookie"],
		Body:          string(raw),
		BodyBytes:     len(raw),
		BodyTruncated: truncated,
		ElapsedMs:     time.Since(start).Milliseconds(),
	}
	if resp.Request != nil && resp.Request.URL != nil {
		if final := resp.Request.URL.String(); final != r.URL {
			out.FinalURL = final
			out.Redirected = true
		}
	}
	return out, nil
}
