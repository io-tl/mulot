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

// GetEntries returns a snapshot of all recorded exchanges. Used by the link
// checker and the auth access-control probe to read each request's status.
func (m *Monitor) GetEntries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		result = append(result, *e)
	}
	return result
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

func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = false
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

