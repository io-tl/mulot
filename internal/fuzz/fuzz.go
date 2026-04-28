// Package fuzz is a minimal Burp-Intruder "sniper" primitive: it takes a base
// HTTP request containing a marker token, substitutes each payload in turn, and
// sends it via httpx. The model supplies the payloads and the methodology; this
// package is the mechanism.
//
// v1 is deliberately simple: single marker, one payload set, sequential sends,
// and match on status/regex. No pitchfork/cluster-bomb modes, no concurrency,
// no payload generators.
package fuzz

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/io-tl/mulot/internal/httpx"
)

// MaxPayloads caps a single run so an agent can't accidentally fire an unbounded
// number of requests. Exceeding it is an explicit error (no silent truncation),
// so the caller splits into batches.
const MaxPayloads = 500

// DefaultMarker is the token replaced by each payload when none is given.
const DefaultMarker = "FUZZ"

type Params struct {
	Base        httpx.Request // template request (url/method/headers/body/cookies/...)
	Marker      string        // token to replace; defaults to DefaultMarker
	Payloads    []string      // inline payload set (required, non-empty)
	MatchStatus int           // 0 = ignore
	MatchRegex  string        // "" = ignore
}

type Result struct {
	Payload string `json:"payload"`
	Status  int    `json:"status"`
	Length  int    `json:"length"`
	TimeMs  int64  `json:"timeMs"`
	Matched bool   `json:"matched,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Output struct {
	Marker  string   `json:"marker"`
	Count   int      `json:"count"`
	Results []Result `json:"results"`
}

// Run substitutes each payload into the base request and sends it sequentially.
func Run(ctx context.Context, p Params) (*Output, error) {
	if len(p.Payloads) == 0 {
		return nil, fmt.Errorf("payloads is required (non-empty list)")
	}
	if len(p.Payloads) > MaxPayloads {
		return nil, fmt.Errorf("too many payloads: %d exceeds cap of %d — split into batches", len(p.Payloads), MaxPayloads)
	}
	marker := p.Marker
	if marker == "" {
		marker = DefaultMarker
	}

	var re *regexp.Regexp
	if p.MatchRegex != "" {
		var err error
		re, err = regexp.Compile(p.MatchRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid match_regex: %v", err)
		}
	}

	out := &Output{Marker: marker, Count: len(p.Payloads)}
	for _, pl := range p.Payloads {
		req := substitute(p.Base, marker, pl)
		res := Result{Payload: pl}
		resp, err := httpx.Send(ctx, req)
		if err != nil {
			res.Error = err.Error()
			out.Results = append(out.Results, res)
			continue
		}
		res.Status = resp.Status
		res.Length = resp.BodyBytes
		res.TimeMs = resp.ElapsedMs

		// matched is only meaningful when a criterion was supplied; with both,
		// all supplied criteria must hold (AND).
		if p.MatchStatus != 0 || re != nil {
			matched := true
			if p.MatchStatus != 0 && resp.Status != p.MatchStatus {
				matched = false
			}
			if re != nil && !re.MatchString(resp.Body) {
				matched = false
			}
			res.Matched = matched
		}
		out.Results = append(out.Results, res)
	}
	return out, nil
}

// substitute returns a copy of base with marker replaced by payload in the URL,
// body, header values, and cookie values. Header/cookie names are left as-is.
func substitute(base httpx.Request, marker, payload string) httpx.Request {
	rep := func(s string) string { return strings.ReplaceAll(s, marker, payload) }
	r := base
	r.URL = rep(base.URL)
	r.Body = rep(base.Body)
	if base.Headers != nil {
		h := make(map[string]string, len(base.Headers))
		for k, v := range base.Headers {
			h[k] = rep(v)
		}
		r.Headers = h
	}
	if base.Cookies != nil {
		cs := make([]*http.Cookie, len(base.Cookies))
		for i, c := range base.Cookies {
			cc := *c
			cc.Value = rep(c.Value)
			cs[i] = &cc
		}
		r.Cookies = cs
	}
	return r
}
