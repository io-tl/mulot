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

func TestMonitorInFlight(t *testing.T) {
	m := NewMonitor()
	m.entries["1"] = &Entry{done: false}
	m.entries["2"] = &Entry{done: true}
	if n := m.InFlight(); n != 1 {
		t.Errorf("InFlight() = %d, want 1", n)
	}
}
