package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/io-tl/mulot/internal/envcfg"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// TestBrowserLaunchRespectsHeadlessEnv drives the real browser_launch tool
// handler (not just the browser package in isolation) and inspects the
// actual Chromium process' command line, so a regression that re-hardcodes
// the headless default in the MCP handler (as server.go once did) would be
// caught even though browser.New itself still reads MULOT_HEADLESS correctly.
func TestBrowserLaunchRespectsHeadlessEnv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc/<pid>/cmdline, linux-only")
	}

	cases := []struct {
		name         string
		envValue     string
		wantHeadless bool
	}{
		{"unset defaults to headless=true", "", true},
		{"MULOT_HEADLESS=false disables headless", "false", false},
		{"MULOT_HEADLESS=true forces headless", "true", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envcfg.HeadlessVar, tc.envValue)

			s := server.NewMCPServer("mulot-test", "0.0.0", server.WithToolCapabilities(false))
			sess := &session{}
			registerTools(s, sess)

			tool := s.GetTool("browser_launch")
			if tool == nil {
				t.Fatal("browser_launch tool not registered")
			}

			req := mcp.CallToolRequest{Params: mcp.CallToolParams{
				Arguments: map[string]any{
					// Avoid touching the real ~/.mulot/traffic.db from a test.
					"journal_db": filepath.Join(t.TempDir(), "test-traffic.db"),
				},
			}}
			res, err := tool.Handler(context.Background(), req)
			if err != nil {
				t.Fatalf("browser_launch: %v", err)
			}
			if res != nil && res.IsError {
				t.Fatalf("browser_launch returned an error result: %+v", res)
			}
			t.Cleanup(func() {
				if sess.browser != nil {
					sess.browser.Close()
				}
			})

			proc := chromedp.FromContext(sess.tab.Context()).Browser.Process()
			if proc == nil {
				t.Fatal("no browser process found in tab context")
			}
			cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", proc.Pid))
			if err != nil {
				t.Fatalf("read /proc/%d/cmdline: %v", proc.Pid, err)
			}
			hasHeadlessFlag := strings.Contains(string(cmdline), "--headless")
			if hasHeadlessFlag != tc.wantHeadless {
				t.Errorf("--headless present = %v, want %v (cmdline: %q)",
					hasHeadlessFlag, tc.wantHeadless, strings.ReplaceAll(string(cmdline), "\x00", " "))
			}
		})
	}
}
