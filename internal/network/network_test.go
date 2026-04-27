package network

import (
	"testing"
)

func TestMonitorGetEntries(t *testing.T) {
	m := NewMonitor()
	m.entries["1"] = &Entry{RequestID: "1", URL: "http://example.com", Method: "GET", Status: 200}
	m.entries["2"] = &Entry{RequestID: "2", URL: "http://example.com/api", Method: "POST", Status: 201}

	entries := m.GetEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestMonitorGetEntriesByMethod(t *testing.T) {
	m := NewMonitor()
	m.entries["1"] = &Entry{RequestID: "1", Method: "GET", Status: 200}
	m.entries["2"] = &Entry{RequestID: "2", Method: "POST", Status: 201}
	m.entries["3"] = &Entry{RequestID: "3", Method: "GET", Status: 200}

	gets := m.GetEntriesByMethod("GET")
	if len(gets) != 2 {
		t.Fatalf("expected 2 GET entries, got %d", len(gets))
	}

	posts := m.GetEntriesByMethod("POST")
	if len(posts) != 1 {
		t.Fatalf("expected 1 POST entry, got %d", len(posts))
	}
}

func TestMonitorGetFailedEntries(t *testing.T) {
	m := NewMonitor()
	m.entries["1"] = &Entry{RequestID: "1", Status: 200}
	m.entries["2"] = &Entry{RequestID: "2", Status: 404}
	m.entries["3"] = &Entry{RequestID: "3", Failed: true, ErrorText: "net::ERR_CONNECTION_REFUSED"}

	failed := m.GetFailedEntries()
	if len(failed) != 2 {
		t.Fatalf("expected 2 failed entries, got %d", len(failed))
	}
}

func TestMonitorClear(t *testing.T) {
	m := NewMonitor()
	m.entries["1"] = &Entry{RequestID: "1"}
	m.Clear()
	if len(m.GetEntries()) != 0 {
		t.Error("expected empty after clear")
	}
}

func TestCapitalize(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"content-security-policy", "Content-Security-Policy"},
		{"x-frame-options", "X-Frame-Options"},
		{"", ""},
	}
	for _, tt := range tests {
		got := capitalize(tt.in)
		if got != tt.want {
			t.Errorf("capitalize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestGetSecurityHeaders(t *testing.T) {
	entries := []Entry{
		{
			URL:    "http://example.com",
			Status: 200,
			RespHeaders: map[string]string{
				"content-security-policy": "default-src 'self'",
				"x-frame-options":         "DENY",
			},
		},
	}
	result := GetSecurityHeaders(entries)
	if _, ok := result["http://example.com"]; !ok {
		t.Fatal("expected entry for example.com")
	}
	if result["http://example.com"]["content-security-policy"] != "default-src 'self'" {
		t.Error("expected CSP header")
	}
}
