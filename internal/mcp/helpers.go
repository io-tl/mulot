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
