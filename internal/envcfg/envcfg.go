// Package envcfg is the single source of truth for the MULOT_* environment
// variables that set default behavior (user-agent, headless mode, upstream
// proxy) for the browser and the raw HTTP client. Centralizing them here
// means the CLI help text (cmd/mulot) is generated from the same list the
// getters read, so the two can't drift apart.
package envcfg

import (
	"os"
	"strconv"
)

const (
	UserAgentVar = "MULOT_USER_AGENT"
	HeadlessVar  = "MULOT_HEADLESS"
	ProxyVar     = "MULOT_PROXY"
)

// Var describes one MULOT_* environment variable for display (e.g. -h).
type Var struct {
	Name string
	Desc string
}

// Vars lists every supported environment variable; cmd/mulot renders this
// directly into its usage text.
var Vars = []Var{
	{UserAgentVar, "User-Agent sent by http_request/http_fuzz and the browser."},
	{HeadlessVar, "Default headless mode for browser_launch (true/false)."},
	{ProxyVar, "Upstream proxy for the browser (HTTP/SOCKS5) and http_request/http_fuzz (HTTP/HTTPS only)."},
}

// UserAgent returns the configured default User-Agent, or "" if unset.
func UserAgent() string {
	return os.Getenv(UserAgentVar)
}

// Headless returns the configured default headless mode, falling back to
// def when unset or unparseable.
func Headless(def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(HeadlessVar)); err == nil {
		return v
	}
	return def
}

// ProxyURL returns the configured default upstream proxy, or "" if unset.
func ProxyURL() string {
	return os.Getenv(ProxyVar)
}
