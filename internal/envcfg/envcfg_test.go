package envcfg

import "testing"

func TestHeadlessDefaultAndOverride(t *testing.T) {
	t.Setenv(HeadlessVar, "")
	if !Headless(true) {
		t.Error("expected default true when unset")
	}

	t.Setenv(HeadlessVar, "false")
	if Headless(true) {
		t.Error("expected false when MULOT_HEADLESS=false")
	}

	t.Setenv(HeadlessVar, "not-a-bool")
	if !Headless(true) {
		t.Error("expected fallback to default on unparseable value")
	}
}

func TestUserAgentAndProxyURL(t *testing.T) {
	t.Setenv(UserAgentVar, "")
	if got := UserAgent(); got != "" {
		t.Errorf("UserAgent() = %q, want empty", got)
	}
	t.Setenv(UserAgentVar, "custom/1.0")
	if got := UserAgent(); got != "custom/1.0" {
		t.Errorf("UserAgent() = %q, want custom/1.0", got)
	}

	t.Setenv(ProxyVar, "")
	if got := ProxyURL(); got != "" {
		t.Errorf("ProxyURL() = %q, want empty", got)
	}
	t.Setenv(ProxyVar, "http://proxy:8080")
	if got := ProxyURL(); got != "http://proxy:8080" {
		t.Errorf("ProxyURL() = %q, want http://proxy:8080", got)
	}
}

func TestVarsListIsComplete(t *testing.T) {
	want := map[string]bool{UserAgentVar: false, HeadlessVar: false, ProxyVar: false}
	for _, v := range Vars {
		if _, ok := want[v.Name]; !ok {
			t.Errorf("Vars contains unknown entry %q", v.Name)
		}
		want[v.Name] = true
		if v.Desc == "" {
			t.Errorf("Vars entry %q has empty description", v.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("Vars is missing %q", name)
		}
	}
}
