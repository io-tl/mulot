package mcp

import (
	"testing"

	"github.com/io-tl/mulot/internal/fuzz"
)

func TestEncodeBase64(t *testing.T) {
	data := []byte("hello world")
	encoded := encodeBase64(data)
	if encoded != "aGVsbG8gd29ybGQ=" {
		t.Errorf("unexpected encoding: %s", encoded)
	}
}

func TestSummarizeFuzz(t *testing.T) {
	out := &fuzz.Output{
		Count: 4,
		Results: []fuzz.Result{
			{Payload: "admin", Status: 200},
			{Payload: "nope", Status: 404},
			{Payload: "old", Status: 301},
			{Payload: "boom", Status: 0, Error: "dial timeout"},
		},
	}

	// No grep criteria: keep anything that is not a plain 404/no-response.
	s := summarizeFuzz("pages", out, false)
	if s.Wordlist != "pages" || s.Total != 4 {
		t.Fatalf("unexpected header: %+v", s)
	}
	if len(s.Hits) != 2 {
		t.Fatalf("want 2 hits (200,301), got %d: %+v", len(s.Hits), s.Hits)
	}
	if s.StatusCounts["404"] != 1 || s.StatusCounts["200"] != 1 || s.StatusCounts["0"] != 1 {
		t.Errorf("bad histogram: %+v", s.StatusCounts)
	}

	// With grep criteria: only rows flagged Matched survive.
	out.Results[1].Matched = true // pretend the 404 matched a regex
	s2 := summarizeFuzz("pages", out, true)
	if len(s2.Hits) != 1 || s2.Hits[0].Payload != "nope" {
		t.Errorf("criteria mode should keep only matched rows, got %+v", s2.Hits)
	}
}
