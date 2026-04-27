package network

import (
	"context"
	"sync"

	cdpNetwork "github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type Entry struct {
	RequestID   string            `json:"requestId"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Status      int64             `json:"status"`
	MimeType    string            `json:"mimeType,omitempty"`
	ReqHeaders  map[string]string `json:"requestHeaders,omitempty"`
	RespHeaders map[string]string `json:"responseHeaders,omitempty"`
	PostData    string            `json:"postData,omitempty"`
	BodySize    float64           `json:"bodySize,omitempty"`
	Failed      bool              `json:"failed,omitempty"`
	ErrorText   string            `json:"errorText,omitempty"`
	done        bool              `json:"-"`
}

type Monitor struct {
	mu      sync.Mutex
	entries map[string]*Entry
	active  bool
}

func NewMonitor() *Monitor {
	return &Monitor{
		entries: make(map[string]*Entry),
	}
}

func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	m.active = true
	m.mu.Unlock()

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.active {
			return
		}

		switch e := ev.(type) {
		case *cdpNetwork.EventRequestWillBeSent:
			entry := &Entry{
				RequestID: string(e.RequestID),
				URL:       e.Request.URL,
				Method:    e.Request.Method,
			}
			if e.Request.HasPostData {
				for _, pde := range e.Request.PostDataEntries {
					entry.PostData += pde.Bytes
				}
			}
			headers := make(map[string]string)
			for k, v := range e.Request.Headers {
				if s, ok := v.(string); ok {
					headers[k] = s
				}
			}
			entry.ReqHeaders = headers
			m.entries[string(e.RequestID)] = entry

		case *cdpNetwork.EventResponseReceived:
			if entry, ok := m.entries[string(e.RequestID)]; ok {
				entry.Status = e.Response.Status
				entry.MimeType = e.Response.MimeType
				respHeaders := make(map[string]string)
				for k, v := range e.Response.Headers {
					if s, ok := v.(string); ok {
						respHeaders[k] = s
					}
				}
				entry.RespHeaders = respHeaders
			}

		case *cdpNetwork.EventLoadingFinished:
			if entry, ok := m.entries[string(e.RequestID)]; ok {
				entry.BodySize = e.EncodedDataLength
				entry.done = true
			}

		case *cdpNetwork.EventLoadingFailed:
			if entry, ok := m.entries[string(e.RequestID)]; ok {
				entry.Failed = true
				entry.ErrorText = e.ErrorText
				entry.done = true
			}
		}
	})

	return chromedp.Run(ctx, cdpNetwork.Enable())
}

func (m *Monitor) GetEntries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		result = append(result, *e)
	}
	return result
}

func (m *Monitor) GetEntriesByMethod(method string) []Entry {
	all := m.GetEntries()
	var filtered []Entry
	for _, e := range all {
		if e.Method == method {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (m *Monitor) GetFailedEntries() []Entry {
	all := m.GetEntries()
	var filtered []Entry
	for _, e := range all {
		if e.Failed || e.Status >= 400 {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// InFlight returns the number of requests that have started but not yet
// finished or failed. Used by the wait package to detect network idle.
// Note: persistent connections (SSE, websockets, long-poll) never complete
// and will keep this above zero.
func (m *Monitor) InFlight() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.entries {
		if !e.done {
			n++
		}
	}
	return n
}

func (m *Monitor) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = make(map[string]*Entry)
}

func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = false
}

func GetResponseBody(ctx context.Context, requestID string) (string, error) {
	var body []byte
	err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			body, err = cdpNetwork.GetResponseBody(cdpNetwork.RequestID(requestID)).Do(ctx)
			return err
		}),
	)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func GetCookies(ctx context.Context) ([]*cdpNetwork.Cookie, error) {
	var cookies []*cdpNetwork.Cookie
	err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			cookies, err = cdpNetwork.GetCookies().Do(ctx)
			return err
		}),
	)
	return cookies, err
}

func SetCookie(ctx context.Context, name, value, domain, path string) error {
	return chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return cdpNetwork.SetCookie(name, value).
				WithDomain(domain).
				WithPath(path).
				Do(ctx)
		}),
	)
}

func ClearCookies(ctx context.Context) error {
	return chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return cdpNetwork.ClearBrowserCookies().Do(ctx)
		}),
	)
}

func GetSecurityHeaders(entries []Entry) map[string]map[string]string {
	result := make(map[string]map[string]string)
	secHeaders := []string{
		"content-security-policy",
		"x-content-type-options",
		"x-frame-options",
		"strict-transport-security",
		"x-xss-protection",
		"referrer-policy",
		"permissions-policy",
		"access-control-allow-origin",
	}

	for _, e := range entries {
		if e.RespHeaders == nil {
			continue
		}
		found := make(map[string]string)
		for _, h := range secHeaders {
			if v, ok := e.RespHeaders[h]; ok {
				found[h] = v
			} else if v, ok := e.RespHeaders[capitalize(h)]; ok {
				found[h] = v
			}
		}
		if len(found) > 0 || (e.Status >= 200 && e.Status < 400) {
			result[e.URL] = found
		}
	}
	return result
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	result := make([]byte, len(s))
	upper := true
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			result[i] = '-'
			upper = true
		} else if upper && s[i] >= 'a' && s[i] <= 'z' {
			result[i] = s[i] - 32
			upper = false
		} else {
			result[i] = s[i]
			upper = false
		}
	}
	return string(result)
}
