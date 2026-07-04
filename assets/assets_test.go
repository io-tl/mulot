package assets

import (
	"strings"
	"testing"
)

func TestSkillsIncludesKnownStacks(t *testing.T) {
	got := Skills()
	if len(got) == 0 {
		t.Fatal("Skills() returned nothing")
	}
	want := map[string]bool{"php": false, "python": false, "nodejs": false}
	for _, s := range got {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected stack %q in %v", name, got)
		}
	}
}

func TestXMLSkillEmbedded(t *testing.T) {
	// xml is a cross-stack capability playbook, discovered like any other stack.
	found := false
	for _, s := range Skills() {
		if s == "xml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected \"xml\" in Skills() = %v", Skills())
	}
	content, err := LoadSkill("xml")
	if err != nil {
		t.Fatalf("LoadSkill(xml): %v", err)
	}
	// One marker per file, so a dropped/renamed file trips the test.
	for _, marker := range []string{
		"XML attack surface", "Find the XML sinks", "in-band file read",
		"blind, out-of-band", "XPath", "XSLT injection",
		"Signature Wrapping", "Parser & WAF bypasses",
	} {
		if !strings.Contains(content, marker) {
			t.Errorf("xml playbook missing %q", marker)
		}
	}
}

func TestWorkflowNonEmpty(t *testing.T) {
	wf, err := Workflow()
	if err != nil {
		t.Fatalf("Workflow: %v", err)
	}
	if strings.TrimSpace(wf) == "" {
		t.Fatal("workflow is empty")
	}
}

func TestLoadSkill(t *testing.T) {
	content, err := LoadSkill("php")
	if err != nil {
		t.Fatalf("LoadSkill: %v", err)
	}
	if strings.TrimSpace(content) == "" {
		t.Fatal("php playbooks empty")
	}
	// Unknown stacks are reported inline, not fatal.
	mixed, err := LoadSkill("php", "doesnotexist")
	if err != nil {
		t.Fatalf("LoadSkill mixed: %v", err)
	}
	if !strings.Contains(mixed, "unknown stack: doesnotexist") {
		t.Error("expected inline unknown-stack note")
	}
}

func TestWordlistParsing(t *testing.T) {
	for _, tag := range []string{"passwords", "params", "pages"} {
		entries, err := Wordlist(tag)
		if err != nil {
			t.Fatalf("Wordlist(%q): %v", tag, err)
		}
		if len(entries) == 0 {
			t.Fatalf("wordlist %q is empty", tag)
		}
		for _, e := range entries {
			if e == "" {
				t.Errorf("wordlist %q has a blank entry", tag)
			}
			if strings.HasPrefix(e, "#") {
				t.Errorf("wordlist %q kept a comment line: %q", tag, e)
			}
			if e != strings.TrimSpace(e) {
				t.Errorf("wordlist %q entry not trimmed: %q", tag, e)
			}
		}
	}
	if _, err := Wordlist("nope"); err == nil {
		t.Error("expected error for unknown wordlist tag")
	}
}

func TestWordlistTags(t *testing.T) {
	tags := WordlistTags()
	want := map[string]bool{"passwords": false, "params": false, "pages": false}
	for _, tg := range tags {
		if _, ok := want[tg]; ok {
			want[tg] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected wordlist tag %q in %v", name, tags)
		}
	}
}

func TestJSCrypto(t *testing.T) {
	src, err := JS("crypto")
	if err != nil {
		t.Fatalf("JS(crypto): %v", err)
	}
	if !strings.Contains(src, "mulotCrypto") {
		t.Error("crypto.js does not define mulotCrypto")
	}
	if _, err := JS("nope"); err == nil {
		t.Error("expected error for unknown js helper")
	}
}
