package mcp

import "testing"

// The coercion helpers exist so a model that stringifies its tool-call arguments
// ("200" instead of 200, "true" instead of true) still drives the tool, instead
// of having the filter/flag silently dropped by a strict `.(float64)`/`.(bool)`
// assertion. These tables pin the accepted forms.

func TestArgFloat(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want float64
		ok   bool
	}{
		{"float", float64(200), 200, true},
		{"int", 200, 200, true},
		{"numeric string", "200", 200, true},
		{"padded string", "  200 ", 200, true},
		{"float string", "1.5", 1.5, true},
		{"empty string", "", 0, false},
		{"garbage string", "abc", 0, false},
		{"bool", true, 0, false},
		{"absent", nil, 0, false},
	}
	for _, c := range cases {
		got, ok := argFloat(map[string]any{"k": c.v}, "k")
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: argFloat = %v, %v; want %v, %v", c.name, got, ok, c.want, c.ok)
		}
	}
	// A missing key (not just a nil value) also yields (0, false).
	if got, ok := argFloat(map[string]any{}, "missing"); ok || got != 0 {
		t.Errorf("missing key: argFloat = %v, %v; want 0, false", got, ok)
	}
}

func TestArgInt(t *testing.T) {
	if v, ok := argInt(map[string]any{"k": "404"}, "k"); !ok || v != 404 {
		t.Errorf("argInt(\"404\") = %v, %v; want 404, true", v, ok)
	}
	if v, ok := argInt(map[string]any{"k": float64(1.9)}, "k"); !ok || v != 1 {
		t.Errorf("argInt(1.9) = %v, %v; want 1 (truncated), true", v, ok)
	}
	if _, ok := argInt(map[string]any{"k": "x"}, "k"); ok {
		t.Errorf("argInt(\"x\") ok = true; want false")
	}
}

func TestArgBool(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want bool
		ok   bool
	}{
		{"true", true, true, true},
		{"false", false, false, true},
		{"string true", "true", true, true},
		{"string TRUE padded", " TRUE ", true, true},
		{"string 1", "1", true, true},
		{"string yes", "yes", true, true},
		{"string false", "false", false, true},
		{"string 0", "0", false, true},
		{"number 1", float64(1), true, true},
		{"number 0", float64(0), false, true},
		{"garbage", "maybe", false, false},
		{"absent", nil, false, false},
	}
	for _, c := range cases {
		got, ok := argBool(map[string]any{"k": c.v}, "k")
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: argBool = %v, %v; want %v, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestArgString(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want string
		ok   bool
	}{
		{"string", "x", "x", true},
		{"empty string", "", "", true}, // present-but-empty is (‑, true); caller checks emptiness
		{"int-valued", float64(200), "200", true},
		{"float-valued", float64(1.5), "1.5", true},
		{"bool-valued", true, "true", true},
		{"absent", nil, "", false},
	}
	for _, c := range cases {
		got, ok := argString(map[string]any{"k": c.v}, "k")
		if ok != c.ok || got != c.want {
			t.Errorf("%s: argString = %q, %v; want %q, %v", c.name, got, ok, c.want, c.ok)
		}
	}
	if _, ok := argString(map[string]any{}, "missing"); ok {
		t.Errorf("missing key: argString ok = true; want false")
	}
}
