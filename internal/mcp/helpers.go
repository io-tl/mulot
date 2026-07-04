package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/io-tl/mulot/internal/dom"
	"github.com/io-tl/mulot/internal/network"
)

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// writeTempUpload stages file content under a fresh temp dir using the given
// filename (so the extension the upload filter sees is controlled by the
// caller) and returns the path. The temp dir is left in place for the lifetime
// of the process; the OS reclaims it.
func writeTempUpload(filename, content string) (string, error) {
	dir, err := os.MkdirTemp("", "mulot-upload-")
	if err != nil {
		return "", err
	}
	// Guard against path traversal in the supplied filename.
	path := filepath.Join(dir, filepath.Base(filename))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// argStringMap reads an argument that is either a JSON object (delivered as a
// map) or a JSON-object string, and flattens it to string values.
func argStringMap(v any) map[string]string {
	out := map[string]string{}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			out[k] = fmt.Sprint(val)
		}
	case string:
		if strings.TrimSpace(t) != "" {
			var m map[string]any
			if json.Unmarshal([]byte(t), &m) == nil {
				for k, val := range m {
					out[k] = fmt.Sprint(val)
				}
			}
		}
	}
	return out
}

// argFloat reads an argument as a float64, tolerating either a JSON number
// (float64, the normal case) or a numeric string ("200") — several tool-calling
// models emit every argument value as a string. Returns (0, false) when the key
// is absent, empty, or not coercible, so a caller's `if v, ok := argFloat(...)`
// guard behaves exactly like the old `.(float64)` assertion for well-typed input.
func argFloat(args map[string]any, key string) (float64, bool) {
	switch v := args[key].(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f, true
		}
	case string:
		if s := strings.TrimSpace(v); s != "" {
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

// argInt is argFloat truncated to an int.
func argInt(args map[string]any, key string) (int, bool) {
	f, ok := argFloat(args, key)
	return int(f), ok
}

// argBool reads an argument as a bool, tolerating a real JSON bool, the common
// stringified forms ("true"/"false"/"1"/"0"/"yes"/"no"), or a 0/1 number.
// Returns (false, false) when the key is absent or not coercible.
func argBool(args map[string]any, key string) (bool, bool) {
	switch v := args[key].(type) {
	case bool:
		return v, true
	case float64:
		return v != 0, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "y":
			return true, true
		case "false", "0", "no", "n":
			return false, true
		}
	}
	return false, false
}

// argString reads an argument as a string, tolerating a numeric or boolean value
// delivered where a string was expected (a model may send 200 instead of "200").
// Returns ("", false) when the key is absent or null — callers use the ok flag to
// enforce required fields instead of a bare `.(string)` assertion that panics.
func argString(args map[string]any, key string) (string, bool) {
	switch v := args[key].(type) {
	case string:
		return v, true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}

// sessionCookiesFor returns the browser's cookies that apply to rawURL's host,
// so an out-of-browser HTTP request can carry the authenticated session.
func sessionCookiesFor(ctx context.Context, rawURL string) []*http.Cookie {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	cookies, err := network.GetCookies(ctx)
	if err != nil {
		return nil
	}
	var out []*http.Cookie
	for _, c := range cookies {
		d := strings.TrimPrefix(c.Domain, ".")
		if host == d || strings.HasSuffix(host, "."+d) {
			out = append(out, &http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	return out
}

// resolveTarget returns the CSS selector to act on, accepting either a snapshot
// ref ("e7", preferred) or a raw CSS selector. Exactly one must be provided.
func resolveTarget(args map[string]any) (string, error) {
	if ref, _ := args["ref"].(string); ref != "" {
		return dom.RefSelector(ref), nil
	}
	if sel, _ := args["selector"].(string); sel != "" {
		return sel, nil
	}
	return "", fmt.Errorf("provide either 'ref' (from browser_snapshot) or 'selector'")
}
